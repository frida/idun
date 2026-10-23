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
			var message = new ByteArray ();
			append_varint_field (message, 2, type);
			append_bytes_field (message, 5, group_id.data);
			append_varint_field (message, 7, flag);
			return message.data;
		}

		private static void append_varint_field (ByteArray message, int field, uint64 value) {
			append_varint (message, (uint64) field << 3);
			append_varint (message, value);
		}

		private static void append_bytes_field (ByteArray message, int field, uint8[] value) {
			append_varint (message, ((uint64) field << 3) | 2);
			append_varint (message, value.length);
			message.append (value);
		}

		private static void append_varint (ByteArray message, uint64 value) {
			do {
				uint8 piece = (uint8) (value & 0x7f);
				value >>= 7;
				if (value != 0)
					piece |= 0x80;
				message.append ({ piece });
			} while (value != 0);
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
