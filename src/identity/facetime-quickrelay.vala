using Efni;

namespace Idun {
	/**
	 * The QuickRelay allocation a device requests to join a call's media: the answer is
	 * the relay address and the session credentials every participant keys its relayed
	 * media and control to. The request names the call's fanout group and its member
	 * count and rides the quickrelay push topic; the matching allocation arrives as its
	 * own notification on the same topic, tagged with the request id.
	 */
	public sealed class FaceTimeQuickRelay {
		private const int ALLOCATE_REQUEST = 200;
		private const int REQUEST_TYPE_ALLOCATE = 3;
		private const int RELAY_VERSION = 25;
		private const string SERVICE_TOPIC = "com.apple.private.alloy.facetime.multi";

		public static uint8[] build_allocation_request (string group_id, uint32 member_count,
				string handle, Bytes push_token, uint8[] request_id) throws Efni.Error {
			var request = new Plist ();
			request.set_integer ("c", ALLOCATE_REQUEST);
			request.set_bytes ("U", new Bytes (request_id));
			request.set_string ("sP", handle);
			request.set_bytes ("t", push_token);
			request.set_integer ("qr", 0);
			request.set_bytes ("qids", new Bytes (uuid_to_bytes (group_id)));
			request.set_string ("qgid", group_id);
			request.set_integer ("qgmc", member_count);
			request.set_string ("qai", SERVICE_TOPIC);
			request.set_integer ("qat", REQUEST_TYPE_ALLOCATE);
			request.set_integer ("qv", RELAY_VERSION);
			return request.to_binary ();
		}

		/**
		 * The external pre-shared key the relay's QUIC handshake authenticates with,
		 * derived from the allocation's session key under a client-chosen salt. The salt
		 * travels in the identity so the relay can rederive the same key.
		 */
		public static uint8[] derive_quic_psk (Bytes session_key, uint8[] salt) throws Efni.Error {
			return hkdf (session_key.get_data (), salt, "QR-QUIC-V0".data, 32);
		}

		public static uint8[] build_quic_psk_identity (uint8[] salt, Bytes session_token) {
			var identity = new BufferBuilder ();
			identity.append_uint8 (0);
			identity.append_data (salt);
			identity.append_bytes (session_token);
			return identity.build ().get_data ();
		}

		/**
		 * The hop-by-hop key protecting this device's media to the relay, bound to the
		 * relay and this device so each link derives its own.
		 */
		public static uint8[] derive_hop_key (Bytes session_key, uint8[] salt, Bytes relay_id,
				int64 participant_id) throws Efni.Error {
			return hkdf (session_key.get_data (), salt,
				relay_context ("QR-HBH-KDF", relay_id, participant_id), 64);
		}

		/**
		 * The session key material the relay's participant map is keyed from, so a device
		 * can resolve the relay's mapped participant ids back to the call's own.
		 */
		public static uint8[] derive_session_key_material (Bytes session_key, uint8[] salt,
				Bytes relay_id, int64 participant_id) throws Efni.Error {
			return hkdf (session_key.get_data (), salt,
				relay_context ("QuickRelay KDF", relay_id, participant_id), 48);
		}

		private static uint8[] relay_context (string label, Bytes relay_id, int64 participant_id) {
			var info = new BufferBuilder (BIG_ENDIAN);
			info.append_data (label.data);
			info.append_bytes (relay_id);
			info.append_uint64 (participant_id);
			return info.build ().get_data ();
		}

		private static uint8[] hkdf (uint8[] session_key, uint8[] salt, uint8[] info, int length)
				throws Efni.Error {
			return TetraCrypto.hkdf_extract_and_expand (OpenSSL.ShortName.sha256, session_key, salt,
				info, length);
		}

		public static uint8[] uuid_to_bytes (string uuid) throws Efni.Error {
			var bytes = new uint8[16];
			int written = 0;
			for (int i = 0; i != uuid.length && written != 16; i++) {
				char high = uuid[i];
				if (high == '-')
					continue;
				char low = uuid[++i];
				bytes[written++] = (uint8) ((hex_value (high) << 4) | hex_value (low));
			}
			if (written != 16)
				throw new Efni.Error.PROTOCOL ("Malformed call group identifier");
			return bytes;
		}

		private static int hex_value (char c) {
			if (c >= '0' && c <= '9')
				return c - '0';
			if (c >= 'a' && c <= 'f')
				return c - 'a' + 10;
			return c - 'A' + 10;
		}
	}

	/**
	 * A granted QuickRelay allocation: the relay endpoint to reach and the session keys
	 * and participant ids the call's media and control bind to. One arrives for each
	 * allocation request a device makes, carrying the id it can be matched back by.
	 */
	public sealed class FaceTimeAllocation : Object {
		public Bytes request_id { get; set; }
		public Bytes relay_ip { get; set; }
		public uint16 relay_port { get; set; }
		public Bytes session_token { get; set; }
		public Bytes session_key { get; set; }
		public Bytes session_id { get; set; }
		public Bytes relay_id { get; set; }
		public int64 participant_id { get; set; }

		public static FaceTimeAllocation parse (uint8[] notification) throws Efni.Error {
			try {
				var payload = new Plist.from_data (notification);
				return new FaceTimeAllocation () {
					request_id = payload.get_bytes ("U"),
					relay_ip = payload.get_bytes ("qrip"),
					relay_port = (uint16) payload.get_integer ("qrp"),
					session_token = payload.get_bytes ("qrst"),
					session_key = payload.get_bytes ("qrsk"),
					session_id = payload.get_bytes ("qids"),
					relay_id = payload.get_bytes ("qrsi"),
					participant_id = payload.get_integer ("qri")
				};
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed QuickRelay allocation: %s", e.message);
			}
		}

		public bool answers (uint8[] expected_request_id) {
			return request_id.compare (new Bytes (expected_request_id)) == 0;
		}
	}
}
