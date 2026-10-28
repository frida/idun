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
