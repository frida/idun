using Efni;

namespace Idun {
	/**
	 * A FaceTime endpoint on the call-signaling topic. Once registration has made the
	 * account ring this device, the endpoint subscribes to the signaling topics and
	 * answers an invitation by declining it: a pair-encrypted ConversationMessage
	 * addressed back to the caller over the push courier.
	 */
	public sealed class FaceTimeEndpoint : Object {
		public ApnsCourier courier {
			get;
			construct;
		}

		public PairCrypto crypto {
			get;
			construct;
		}

		public string handle {
			get;
			construct;
		}

		private const int CONVERSATION_MESSAGE = 242;
		private const int DECLINE = 9;
		private const int MEDIA_WRAP_MODE = 1;
		private const int JOIN_NOTIFICATION = 2;
		private const int ACCEPT = 3;
		private const int ANSWER_VERSION = 5;
		private const string DEVICE_MODEL = "Mac17,2";
		private const string DEVICE_BUILD = "2235.63.5.2";
		private const string DEVICE_HARDWARE = "26A428";
		private const int64 PROTOCOL_VERSION = 26006000;
		private const uint64 DECLINE_FLAG = 0xffffffff;

		private const string SIGNALING_TOPIC = "com.apple.private.alloy.facetime.multi";
		private const string[] TOPICS = {
			"com.apple.private.alloy.facetime.multi",
			"com.apple.private.alloy.facetime.video",
			"com.apple.private.alloy.quickrelay",
			"com.apple.private.ids",
		};

		public FaceTimeEndpoint (ApnsCourier courier, PairCrypto crypto, string handle) {
			Object (courier: courier, crypto: crypto, handle: handle);
		}

		public signal void notification_received (Variant notification);

		public async void listen (Cancellable? cancellable = null) throws Efni.Error, IOError {
			yield courier.subscribe (TOPICS, cancellable);
		}

		public async void run (uint ping_interval = 30, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			uint pinger = Timeout.add_seconds (ping_interval, () => {
				courier.ping.begin (cancellable);
				return Source.CONTINUE;
			});
			try {
				while (cancellable == null || !cancellable.is_cancelled ())
					notification_received (yield courier.receive (cancellable));
			} finally {
				Source.remove (pinger);
			}
		}

		public CallInvitation open_invitation (Variant notification, Gee.Collection<PeerIdentity> senders)
				throws Efni.Error {
			Variant? payload = notification.lookup_value ("payload", new VariantType ("a{sv}"));
			if (payload == null)
				throw new Efni.Error.PROTOCOL ("FaceTime notification carried no payload");

			Variant? sealed = payload.lookup_value ("P", new VariantType ("ay"));
			Variant? sender = payload.lookup_value ("sP", VariantType.STRING);
			Variant? token = payload.lookup_value ("t", new VariantType ("ay"));
			if (sealed == null || sender == null || token == null)
				throw new Efni.Error.PROTOCOL ("FaceTime invitation is missing routing fields");

			Bytes sender_token = token.get_data_as_bytes ();
			PeerIdentity caller = identity_for_token (senders, sender_token);
			uint8[] invitation = crypto.decrypt (sealed.get_data_as_bytes ());

			string group_id;
			try {
				group_id = new Plist.from_data (invitation).get_string ("fanout-groupID-key");
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed FaceTime invitation: %s", e.message);
			}

			return new CallInvitation (group_id, sender.get_string (), sender_token, caller.identity_key);
		}

		/**
		 * Decrypt an incoming pair-tetra FaceTime message and, when it is a genuine call
		 * invitation, return the call it opens. The caller resolves the sender's handle to
		 * its registered devices so the signing key, push token and Kyber public key that
		 * bind the key agreement can be read back; Idun's own NGM identity supplies the
		 * responder half. In-call session updates—media-key announcements or peers' join
		 * status—decrypt the same way but are not answerable calls, so they return null.
		 */
		public FaceTimeCall? open_tetra_invitation (Variant notification,
				Gee.Collection<PeerIdentity> senders, NgmIdentity ngm, bool verify = true)
				throws Efni.Error {
			Variant? payload = notification.lookup_value ("payload", new VariantType ("a{sv}"));
			if (payload == null)
				throw new Efni.Error.PROTOCOL ("FaceTime notification carried no payload");

			Variant? sealed = payload.lookup_value ("P", new VariantType ("ay"));
			Variant? sender = payload.lookup_value ("sP", VariantType.STRING);
			Variant? token = payload.lookup_value ("t", new VariantType ("ay"));
			if (sealed == null || sender == null || token == null)
				throw new Efni.Error.PROTOCOL ("FaceTime invitation is missing routing fields");

			PeerIdentity caller = identity_for_token (senders, token.get_data_as_bytes ());
			if (caller.ngm_prekey == null)
				throw new Efni.Error.PROTOCOL ("Sender published no NGM prekey to open a pair-tetra invitation");
			NgmPeerPrekey peer = caller.ngm_prekey;

			TetraMessage tetra = TetraMessage.unwrap (sealed.get_data_as_bytes ().get_data ());
			if (tetra.kem_encapsulation == null)
				throw new Efni.Error.PROTOCOL ("Pair-tetra invitation carries no Kyber encapsulation");

			var context = new TetraRootContext (
				new Bytes (sender.get_string ().data),
				caller.push_token,
				peer.signing_point,
				new Bytes (handle.data),
				courier.push_token,
				new Bytes (ngm.signing_compact_key ()),
				ngm.kem_public);

			var session = TetraSession.establish_as_receiver (ngm.signing_key, context, ngm.prekey_key,
				ngm.kem_secret.get_data (), tetra.ecdh_public_key.get_data (),
				tetra.kem_encapsulation.get_data ());

			var bindings = new TetraBinding[] {
				new TetraBinding (new Bytes (sender.get_string ().data), caller.push_token,
					peer.signing_point),
				new TetraBinding (new Bytes (handle.data), courier.push_token,
					new Bytes (ngm.signing_compact_key ()))
			};

			uint8[] invitation = session.open (tetra.serialize (), peer.signing_point.get_data (),
				SIGNALING_TOPIC.data, bindings, verify);

			string group_id;
			try {
				var decoded = new Plist.from_data (invitation);
				bool carries_media_offer = decoded.has ("participant-data-key");
				if (!carries_media_offer)
					return null;
				group_id = decoded.get_string ("fanout-groupID-key");
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed FaceTime invitation: %s", e.message);
			}

			return new FaceTimeCall (courier, session, handle, sender.get_string (), caller.push_token,
				group_id, invitation, bindings);
		}

		private static PeerIdentity identity_for_token (Gee.Collection<PeerIdentity> senders, Bytes token)
				throws Efni.Error {
			foreach (PeerIdentity sender in senders) {
				if (sender.push_token.compare (token) == 0)
					return sender;
			}
			throw new Efni.Error.PROTOCOL ("No registered identity matched the FaceTime invitation sender");
		}

		public async void decline (CallInvitation call, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			uint8[] message = build_conversation_message (DECLINE, call.group_id, DECLINE_FLAG);
			Bytes sealed = crypto.encrypt (call.caller_identity_key, message);
			Bytes envelope = build_envelope (call.caller_uri, sealed);
			yield courier.post (SIGNALING_TOPIC, call.caller_token, envelope, cancellable);
		}

		/**
		 * Generate the ephemeral key-agreement key a call answer advertises as its
		 * ''rtmpk'': the public half is the P-256 point to which peers wrap the SRTP master
		 * keys they share over the media-key material, so a fresh one is minted per call.
		 */
		public static Bytes generate_media_key () throws Efni.Error {
			return TetraCrypto.generate_key_agreement_key ();
		}

		/**
		 * The uncompressed 65-byte P-256 point a media key advertises as its ''rtmpk''.
		 */
		public static uint8[] media_public_point (Bytes media_key) throws Efni.Error {
			return TetraCrypto.public_key_point (media_key);
		}

		/**
		 * Build the first message a call answer sends: the binary property list that
		 * advertises this device's media public key for the call's fanout group, so peers
		 * can wrap the SRTP master keys to it. The payload is sealed and posted like any
		 * other conversation message once the answering session is established.
		 */
		public static uint8[] build_media_announcement (string group_id, uint8[] media_point) {
			var payload = new Plist ();
			payload.set_bytes ("rtmpk", new Bytes (media_point));
			payload.set_integer ("rtmpwm", MEDIA_WRAP_MODE);
			payload.set_string ("s", group_id);
			payload.set_string ("fanout-groupID-key", group_id);
			return payload.to_binary ();
		}

		/**
		 * Resolve this device's participant id for a call. The invitation lists the fanout
		 * group's members as ''token:<hex>/<uri>'' and maps each uri to the participant ids
		 * of its devices in member order, so a device finds its id by its position among the
		 * members that share its uri.
		 */
		public static int64 resolve_participant_id (string[] members, string uri, string token_hex,
				int64[] candidates) throws Efni.Error {
			int index = 0;
			foreach (string member in members) {
				string entry = member.substring ("token:".length);
				int slash = entry.index_of_char ('/');
				if (entry.substring (slash + 1) != uri)
					continue;
				if (entry.substring (0, slash) == token_hex)
					return candidates[index];
				index++;
			}
			throw new Efni.Error.PROTOCOL ("This device is not a member of the call");
		}

		/**
		 * Build the answer a one-to-one call expects: the binary property list carrying the
		 * conversation message that accepts the call, naming this device's model so the
		 * caller can present the connected participant.
		 */
		public static uint8[] build_call_answer (string group_id) {
			uint8[] call_info = new ProtobufWriter ()
				.append_varint (1, 1805318279)
				.append_varint (2, 1)
				.append_bytes (3, DEVICE_MODEL.data)
				.append_bytes (4, DEVICE_BUILD.data)
				.append_bytes (5, DEVICE_HARDWARE.data)
				.data;
			uint8[] answer = new ProtobufWriter ()
				.append_bytes (3, call_info)
				.data;
			uint8[] conversation = new ProtobufWriter ()
				.append_varint (1, 1)
				.append_varint (2, ACCEPT)
				.append_varint (3, 1)
				.append_bytes (4, answer)
				.append_varint (8, 1)
				.append_bytes (9, Uuid.string_random ().up ().data)
				.data;

			var payload = new Plist ();
			payload.set_string ("p", Uuid.string_random ().up ());
			payload.set_bytes ("c", new Bytes (conversation));
			payload.set_boolean ("pclm", true);
			payload.set_boolean ("mi", true);
			payload.set_integer ("v", ANSWER_VERSION);
			payload.set_boolean ("sqr", true);
			payload.set_boolean ("cc", true);
			payload.set_string ("s", group_id);
			return payload.to_binary ();
		}

		/**
		 * Build the join-status message a call answer sends: the binary property list that
		 * declares this device as a joining, non-initiating participant of the call's fanout
		 * group, naming the group members and this device's participant id so the caller can
		 * route media to it.
		 */
		public static uint8[] build_join_status (string group_id, string[] members,
				int64 participant_id, uint8[] client_context, uint8[] media_point,
				uint8[] participant_data) {
			var group_members = new PlistArray ();
			foreach (string member in members)
				group_members.add_string (member);

			var payload = new Plist ();
			payload.set_bytes ("client-context-data-key", new Bytes (client_context));
			payload.set_boolean ("is-initiator-key", false);
			payload.set_integer ("rtmpwm", MEDIA_WRAP_MODE);
			payload.set_bytes ("rtmpk", new Bytes (media_point));
			payload.set_bytes ("participant-data-key", new Bytes (participant_data));
			payload.set_string ("fanout-groupID-key", group_id);
			payload.set_array ("fanout-groupMembers-key", group_members);
			payload.set_boolean ("is-u-plus-one-key", true);
			payload.set_integer ("join-notification-key", JOIN_NOTIFICATION);
			payload.set_string ("s", group_id);
			payload.set_integer ("participant-id-key", participant_id);
			return payload.to_binary ();
		}

		/**
		 * Build the key-material message an answering device sends: its freshly minted media
		 * and session master keys, each sealed to the peer's advertised media point, together
		 * with the salts and key indicators the peer needs to bind them to the sender. The
		 * media key protects the SRTP streams and the session key the control channel.
		 */
		public static uint8[] build_key_material (string group_id, string[] uris,
				int64 participant_id, uint8[] peer_point, uint8[] media_key, uint8[] media_salt,
				uint8[] session_key_id, uint8[] session_key, uint8[] session_salt) throws Efni.Error {
			var media = new Plist ();
			media.set_integer ("participantID", participant_id);
			media.set_integer ("rtmpwm", MEDIA_WRAP_MODE);
			media.set_bytes ("mki", new Bytes (FaceTimeMediaCrypto.media_key_indicator (participant_id)));
			media.set_bytes ("mkm", new Bytes (FaceTimeMediaCrypto.wrap_key_material (peer_point, media_key)));
			media.set_bytes ("mks", new Bytes (media_salt));
			media.set_integer ("mkgc", 1);
			media.set_integer ("smkil", 2);

			var session = new Plist ();
			session.set_integer ("participantID", participant_id);
			session.set_integer ("rtmpwm", MEDIA_WRAP_MODE);
			session.set_bytes ("ski", new Bytes (session_key_id));
			session.set_bytes ("skm", new Bytes (FaceTimeMediaCrypto.wrap_key_material (peer_point, session_key)));
			session.set_bytes ("sks", new Bytes (session_salt));
			session.set_integer ("skgc", 1);

			var all_uris = new PlistArray ();
			foreach (string uri in uris)
				all_uris.add_string (uri);

			var payload = new Plist ();
			payload.set_string ("s", group_id);
			payload.set_string ("fanout-groupID-key", group_id);
			payload.set_array ("rtallmkmuri", all_uris);
			payload.set_dict ("rtmkm", media);
			payload.set_dict ("rtskm", session);
			return payload.to_binary ();
		}

		public static uint8[] build_participant_data (string session_uuid, uint32 audio_ssrc,
				uint64 ntp_time, uint32 call_id) throws Efni.Error {
			var data = new FaceTimeParticipantData ();
			data.session_uuid = session_uuid;
			data.audio_ssrc = audio_ssrc;
			data.ntp_time = ntp_time;
			data.device_type = DEVICE_MODEL;
			data.framework_version = DEVICE_BUILD;
			data.os_version = DEVICE_HARDWARE;
			data.call_id = call_id;
			return data.build ();
		}

		private Bytes build_envelope (string caller_uri, Bytes payload) {
			var conversation_id = new uint8[16];
			OpenSSL.Rng.generate (conversation_id);

			var envelope = new Plist ();
			envelope.set_integer ("c", CONVERSATION_MESSAGE);
			envelope.set_string ("E", "pair");
			envelope.set_string ("sP", handle);
			envelope.set_string ("tP", caller_uri);
			envelope.set_bytes ("t", courier.push_token);
			envelope.set_bytes ("U", new Bytes (conversation_id));
			envelope.set_bytes ("P", payload);
			envelope.set_integer ("e", get_real_time () * 1000);
			envelope.set_integer ("v", PROTOCOL_VERSION);
			envelope.set_integer ("siu", 0);
			return new Bytes (envelope.to_xml ().data);
		}

		private static uint8[] build_conversation_message (int type, string group_id, uint64 flag) {
			return new ProtobufWriter ()
				.append_varint (2, type)
				.append_bytes (5, group_id.data)
				.append_varint (7, flag)
				.data;
		}
	}

	/**
	 * An answerable incoming pair-tetra call: the established Tetra session, the caller's
	 * routing, and the decrypted invitation. Answering seals its reply sequence back to
	 * the caller through the same session, so the ratchet that opened the invitation also
	 * authenticates the answer.
	 */
	public sealed class FaceTimeCall : Object {
		public ApnsCourier courier {
			get;
			construct;
		}

		public TetraSession session {
			get;
			construct;
		}

		public string handle {
			get;
			construct;
		}

		public string caller_uri {
			get;
			construct;
		}

		public Bytes caller_token {
			get;
			construct;
		}

		public string group_id {
			get;
			construct;
		}

		public Bytes invitation {
			get;
			construct;
		}

		private TetraBinding[] bindings;
		private Bytes? media_key;
		private uint32 audio_ssrc;
		private string session_uuid;
		private int64 my_participant_id;
		private Bytes media_master_key;
		private Bytes media_master_salt;
		private Bytes session_master_key;
		private Bytes session_master_salt;
		private Bytes session_key_id;

		private const int CONVERSATION_MESSAGE = 242;
		private const int64 PROTOCOL_VERSION = 26006000;
		private const string MEDIA_TOPIC = "com.apple.private.alloy.facetime.multi";
		private const string VIDEO_TOPIC = "com.apple.private.alloy.facetime.video";
		private const string QUICKRELAY_TOPIC = "com.apple.private.alloy.quickrelay";
		private const uint8[] JOIN_CONTEXT = { 0x10, 0x00 };

		internal FaceTimeCall (ApnsCourier courier, TetraSession session, string handle,
				string caller_uri, Bytes caller_token, string group_id, uint8[] invitation,
				owned TetraBinding[] bindings) {
			Object (courier: courier, session: session, handle: handle, caller_uri: caller_uri,
				caller_token: caller_token, group_id: group_id, invitation: new Bytes (invitation));
			this.bindings = (owned) bindings;
		}

		/**
		 * Answer the call. The device mints its media key and advertises its public point
		 * to the call's fanout group, so the caller can wrap the media keys to it; the
		 * remaining key material and media description follow once negotiated.
		 */
		public async void accept (Cancellable? cancellable = null) throws Efni.Error, IOError {
			media_key = FaceTimeEndpoint.generate_media_key ();
			uint8[] media_point = FaceTimeEndpoint.media_public_point (media_key);
			mint_media_keys ();

			try {
				var invite = new Plist.from_data (invitation.get_data ());
				string[] members = read_members (invite);
				my_participant_id = resolve_my_participant_id (invite, members);
				uint8[] caller_point = invite.get_bytes ("rtmpk").get_data ();

				uint8[] participant_data = FaceTimeEndpoint.build_participant_data (session_uuid,
					audio_ssrc, ntp_time (), read_call_id (invite));

				uint8[] allocation_request_id = random_bytes (16).get_data ();
				yield courier.post (QUICKRELAY_TOPIC, caller_token,
					new Bytes (FaceTimeQuickRelay.build_allocation_request (group_id, members.length,
						handle, courier.push_token, allocation_request_id)), cancellable);

				yield post_sealed (FaceTimeEndpoint.build_media_announcement (group_id, media_point),
					MEDIA_TOPIC, cancellable);
				yield post_sealed (FaceTimeEndpoint.build_join_status (group_id, members,
					my_participant_id, JOIN_CONTEXT, media_point, participant_data), MEDIA_TOPIC,
					cancellable);
				yield post_sealed (FaceTimeEndpoint.build_key_material (group_id, member_uris (members),
					my_participant_id, caller_point, media_master_key.get_data (),
					media_master_salt.get_data (), session_key_id.get_data (),
					session_master_key.get_data (), session_master_salt.get_data ()), MEDIA_TOPIC,
					cancellable);
				yield post_sealed (FaceTimeEndpoint.build_call_answer (group_id), VIDEO_TOPIC,
					cancellable);
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed FaceTime invitation: %s", e.message);
			}
		}

		private void mint_media_keys () {
			audio_ssrc = Random.next_int ();
			session_uuid = Uuid.string_random ().up ();
			media_master_key = random_bytes (32);
			media_master_salt = random_bytes (16);
			session_master_key = random_bytes (32);
			session_master_salt = random_bytes (16);
			session_key_id = random_bytes (16);
		}

		private static Bytes random_bytes (int length) {
			var data = new uint8[length];
			OpenSSL.Rng.generate (data);
			return new Bytes (data);
		}

		private static uint64 ntp_time () {
			return ((uint64) (get_real_time () / 1000000 + 2208988800)) << 32;
		}

		private string[] read_members (Plist invite) throws PlistError {
			PlistArray member_list = invite.get_array ("fanout-groupMembers-key");
			var members = new string[member_list.length];
			for (int i = 0; i != member_list.length; i++)
				members[i] = member_list.get_string (i);
			return members;
		}

		private int64 resolve_my_participant_id (Plist invite, string[] members) throws Efni.Error,
				PlistError {
			PlistArray candidates = invite.get_dict ("uri-to-participant-id-key").get_array (handle);
			var ids = new int64[candidates.length];
			for (int i = 0; i != candidates.length; i++)
				ids[i] = candidates.get_integer (i);
			return FaceTimeEndpoint.resolve_participant_id (members, handle,
				token_hex (courier.push_token), ids);
		}

		private static string[] member_uris (string[] members) {
			var uris = new Gee.ArrayList<string> ();
			foreach (string member in members) {
				string uri = member.substring (member.index_of_char ('/') + 1);
				if (!uris.contains (uri))
					uris.add (uri);
			}
			return uris.to_array ();
		}

		private static uint32 read_call_id (Plist invite) throws PlistError, Efni.Error {
			var caller = new Plist.from_binary (invite.get_bytes ("participant-data-key").get_data ());
			var reader = new ProtobufReader (caller.get_bytes ("vcSessionParticipantKeyCallInfoBlob").get_data ());
			while (reader.has_more) {
				uint8 wire_type;
				int field = reader.read_field (out wire_type);
				if (field == 1 && wire_type == 0)
					return (uint32) reader.read_varint ();
				reader.skip (wire_type);
			}
			return 0;
		}

		private static string token_hex (Bytes token) {
			var builder = new StringBuilder ();
			foreach (uint8 b in token.get_data ())
				builder.append_printf ("%02X", b);
			return builder.str;
		}

		private async void post_sealed (uint8[] payload, string topic, Cancellable? cancellable)
				throws Efni.Error, IOError {
			uint8[] sealed = session.seal (payload, topic.data, bindings);
			yield courier.post (topic, caller_token, build_envelope (sealed), cancellable);
		}

		private Bytes build_envelope (uint8[] payload) {
			var conversation_id = new uint8[16];
			OpenSSL.Rng.generate (conversation_id);

			var envelope = new Plist ();
			envelope.set_integer ("c", CONVERSATION_MESSAGE);
			envelope.set_string ("E", "pair-tetra");
			envelope.set_string ("sP", handle);
			envelope.set_string ("tP", caller_uri);
			envelope.set_bytes ("t", courier.push_token);
			envelope.set_bytes ("U", new Bytes (conversation_id));
			envelope.set_bytes ("P", new Bytes (payload));
			envelope.set_integer ("e", get_real_time () * 1000);
			envelope.set_integer ("v", PROTOCOL_VERSION);
			envelope.set_integer ("siu", 0);
			return new Bytes (envelope.to_xml ().data);
		}
	}

	/**
	 * An incoming FaceTime invitation reduced to what a decline needs: the call's
	 * group id, and the caller's handle, push token, and identity key to seal and
	 * address the reply back to.
	 */
	public sealed class CallInvitation : Object {
		public string group_id {
			get;
			construct;
		}

		public string caller_uri {
			get;
			construct;
		}

		public Bytes caller_token {
			get;
			construct;
		}

		public Bytes caller_identity_key {
			get;
			construct;
		}

		public CallInvitation (string group_id, string caller_uri, Bytes caller_token, Bytes caller_identity_key) {
			Object (group_id: group_id, caller_uri: caller_uri, caller_token: caller_token,
				caller_identity_key: caller_identity_key);
		}
	}
}
