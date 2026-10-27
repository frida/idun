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
		 * Decrypt an incoming pair-tetra FaceTime invitation. The caller resolves the
		 * sender's handle to its registered devices so the signing key, push token and
		 * Kyber public key that bind the key agreement can be read back; Idun's own NGM
		 * identity supplies the responder half. The returned plaintext is the invitation
		 * the caller would decline or answer.
		 */
		public FaceTimeCall open_tetra_invitation (Variant notification,
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

			// The transcript's initiator Kyber slot binds the encapsulation the caller sent,
			// not its public key; it reaches the session through establish_as_receiver.
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

			// The signature covers the service topic and a routing binding for each party:
			// the caller as initiator and this device as responder. The session rebuilds
			// the authenticated data from the message's own key indicator and ephemeral key.
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
				group_id = new Plist.from_data (invitation).get_string ("fanout-groupID-key");
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
		 * Build the join-status message a call answer sends: the binary property list that
		 * declares this device as a joining, non-initiating participant of the call's fanout
		 * group, naming the group members and this device's participant id so the caller can
		 * route media to it.
		 */
		public static uint8[] build_join_status (string group_id, string[] members,
				int64 participant_id, uint8[] client_context) {
			var group_members = new PlistArray ();
			foreach (string member in members)
				group_members.add_string (member);

			var payload = new Plist ();
			payload.set_bytes ("client-context-data-key", new Bytes (client_context));
			payload.set_boolean ("is-initiator-key", false);
			payload.set_string ("fanout-groupID-key", group_id);
			payload.set_array ("fanout-groupMembers-key", group_members);
			payload.set_boolean ("is-u-plus-one-key", true);
			payload.set_integer ("join-notification-key", JOIN_NOTIFICATION);
			payload.set_string ("s", group_id);
			payload.set_integer ("participant-id-key", participant_id);
			return payload.to_binary ();
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

		private const int CONVERSATION_MESSAGE = 242;
		private const int64 PROTOCOL_VERSION = 26006000;
		private const string MEDIA_TOPIC = "com.apple.private.alloy.facetime.multi";

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
			uint8[] announcement = FaceTimeEndpoint.build_media_announcement (group_id,
				FaceTimeEndpoint.media_public_point (media_key));
			yield post_sealed (announcement, cancellable);
		}

		private async void post_sealed (uint8[] payload, Cancellable? cancellable)
				throws Efni.Error, IOError {
			uint8[] sealed = session.seal (payload, MEDIA_TOPIC.data, bindings);
			yield courier.post (MEDIA_TOPIC, caller_token, build_envelope (sealed), cancellable);
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
