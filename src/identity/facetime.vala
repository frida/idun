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
			uint8[] invitation = crypto.decrypt (caller.identity_key, sealed.get_data_as_bytes ());

			string group_id;
			try {
				group_id = new Plist.from_data (invitation).get_string ("fanout-groupID-key");
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed FaceTime invitation: %s", e.message);
			}

			return new CallInvitation (group_id, sender.get_string (), sender_token, caller.identity_key);
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
