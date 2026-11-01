using Efni;

namespace Idun {
	/**
	 * The CKKS record zones that hold the account's synced keychain, and the record-sync request
	 * framing to page through one. Each zone carries its key hierarchy (the class keys, wrapped by
	 * the zone's TLK) and the encrypted keychain items; recovering a TLK lets idun decrypt the
	 * zone's items, including the account's Key Transparency signing key.
	 */
	public sealed class CkksZone : Object {
		public const string[] KEYCHAIN_ZONES = {
			"Manatee", "Engram", "Passwords", "SecureObjectSync", "ProtectedCloudStorage",
			"CreditCards", "ApplePay", "WiFi", "Home", "Groups", "Contacts", "Mail",
			"LimitedPeersAllowed", "SE-PTC", "Photos", "AutoUnlock", "Health", "Backstop"
		};

		private const int ID_TYPE_RECORD_ZONE = 6;
		private const int ID_TYPE_USER = 7;

		public static uint8[] record_zone_identifier (string zone, string user_id) {
			return new ProtobufWriter ()
				.append_bytes (1, identifier (zone, ID_TYPE_RECORD_ZONE))
				.append_bytes (2, identifier (user_id, ID_TYPE_USER))
				.data;
		}

		public static uint8[] build_retrieve_changes_request (uint8[] zone_identifier,
				uint8[]? continuation_token, uint64 max_changes = 500) {
			var writer = new ProtobufWriter ();
			if (continuation_token != null)
				writer.append_bytes (1, continuation_token);
			writer.append_bytes (2, zone_identifier);
			writer.append_varint (4, max_changes);
			return writer.data;
		}

		private static uint8[] identifier (string name, int type) {
			return new ProtobufWriter ()
				.append_bytes (1, name.data)
				.append_varint (2, type)
				.data;
		}

		/**
		 * Decode a retrieve-changes page: the records (each change's field 5), the continuation
		 * token for the next page, and the status (1 means more pages follow).
		 */
		public static CkksZonePage parse_page (uint8[] response) throws Efni.Error {
			var records = new Gee.ArrayList<CloudKitRecord> ();
			Bytes continuation = new Bytes ({});
			int64 status = 0;

			var reader = new ProtobufReader (response);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						uint8[]? record = extract_record (reader.read_bytes ());
						if (record != null)
							records.add (CloudKitRecord.parse (record));
						break;
					case 2:
						continuation = new Bytes (reader.read_bytes ());
						break;
					case 4:
						status = (int64) reader.read_varint ();
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}
			return new CkksZonePage (records, continuation, status);
		}

		// Each change carries the record under field 5.
		private static uint8[]? extract_record (uint8[] change) throws Efni.Error {
			var reader = new ProtobufReader (change);
			while (reader.has_more) {
				uint8 wire_type;
				if (reader.read_field (out wire_type) == 5 && wire_type == 2)
					return reader.read_bytes ();
				reader.skip (wire_type);
			}
			return null;
		}
	}

	/**
	 * One page of a zone's record changes.
	 */
	public sealed class CkksZonePage : Object {
		public Gee.List<CloudKitRecord> records {
			get;
			construct;
		}

		public Bytes continuation {
			get;
			construct;
		}

		public int64 status {
			get;
			construct;
		}

		public bool has_more {
			get { return status == 1 && continuation.length > 0; }
		}

		public CkksZonePage (Gee.List<CloudKitRecord> records, Bytes continuation, int64 status) {
			Object (records: records, continuation: continuation, status: status);
		}
	}
}
