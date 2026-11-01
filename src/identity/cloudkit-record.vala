using Efni;

namespace Idun {
	/**
	 * A CloudKit record as Cuttlefish returns it inside a function response: a named record of a
	 * given type whose fields are addressed by name. CKKS carries its key hierarchy — TLK shares
	 * and sync keys — as records of this shape, so recovering a TLK means reading a record's
	 * fields (the receiver peer id, the wrapped key) by their CKKS names.
	 */
	public sealed class CloudKitRecord : Object {
		public string record_name {
			get;
			construct;
		}

		public string record_type {
			get;
			construct;
		}

		private Gee.Map<string, string> string_fields;
		private Gee.Map<string, int64?> int_fields;
		private Gee.Map<string, Bytes> bytes_fields;

		public CloudKitRecord (string record_name, string record_type,
				Gee.Map<string, string> string_fields, Gee.Map<string, int64?> int_fields,
				Gee.Map<string, Bytes> bytes_fields) {
			Object (record_name: record_name, record_type: record_type);
			this.string_fields = string_fields;
			this.int_fields = int_fields;
			this.bytes_fields = bytes_fields;
		}

		public string? string_field (string name) {
			return string_fields.has_key (name) ? string_fields[name] : null;
		}

		public bool has_int_field (string name) {
			return int_fields.has_key (name);
		}

		public int64 int_field (string name) {
			return int_fields.has_key (name) ? int_fields[name] : 0;
		}

		public Bytes? bytes_field (string name) {
			return bytes_fields.has_key (name) ? bytes_fields[name] : null;
		}

		public Gee.List<string> field_names () {
			var names = new Gee.ArrayList<string> ();
			names.add_all (string_fields.keys);
			names.add_all (int_fields.keys);
			names.add_all (bytes_fields.keys);
			return names;
		}

		/**
		 * Parse a serialized CloudKit record. The record carries its name under the record
		 * identifier (field 2 → value → name), its type under field 3, and its fields under the
		 * repeated field 7, each a {identifier, value} pair whose value is a string, signed
		 * integer, or bytes.
		 */
		public static CloudKitRecord parse (uint8[] data) throws Efni.Error {
			string record_name = "";
			string record_type = "";
			var string_fields = new Gee.HashMap<string, string> ();
			var int_fields = new Gee.HashMap<string, int64?> ();
			var bytes_fields = new Gee.HashMap<string, Bytes> ();

			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 2:
						record_name = parse_record_name (reader.read_bytes ());
						break;
					case 3:
						record_type = first_string (reader.read_bytes ());
						break;
					case 7:
						parse_field (reader.read_bytes (), string_fields, int_fields, bytes_fields);
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}

			return new CloudKitRecord (record_name, record_type, string_fields, int_fields,
				bytes_fields);
		}

		// recordIdentifier{ value(1){ name(1) } }
		private static string parse_record_name (uint8[] identifier) throws Efni.Error {
			var reader = new ProtobufReader (identifier);
			while (reader.has_more) {
				uint8 wire_type;
				if (reader.read_field (out wire_type) == 1 && wire_type == 2)
					return first_string (reader.read_bytes ());
				reader.skip (wire_type);
			}
			return "";
		}

		private static void parse_field (uint8[] field, Gee.Map<string, string> string_fields,
				Gee.Map<string, int64?> int_fields, Gee.Map<string, Bytes> bytes_fields)
				throws Efni.Error {
			string name = "";
			uint8[]? value = null;
			var reader = new ProtobufReader (field);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						name = first_string (reader.read_bytes ());
						break;
					case 2:
						value = reader.read_bytes ();
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}
			if (name == "" || value == null)
				return;

			var reader2 = new ProtobufReader (value);
			while (reader2.has_more) {
				uint8 wire_type;
				switch (reader2.read_field (out wire_type)) {
					case 2:
						bytes_fields[name] = new Bytes (reader2.read_bytes ());
						return;
					case 4:
						int_fields[name] = (int64) reader2.read_varint ();
						return;
					case 7:
						string_fields[name] = reader2.read_string ();
						return;
					case 9:
						// referenceValue: { type(1), recordIdentifier(2){ value(1){ name(1) } } }
						string_fields[name] = reference_name (reader2.read_bytes ());
						return;
					default:
						reader2.skip (wire_type);
						break;
				}
			}
		}

		private static string reference_name (uint8[] reference) throws Efni.Error {
			var reader = new ProtobufReader (reference);
			while (reader.has_more) {
				uint8 wire_type;
				if (reader.read_field (out wire_type) == 2 && wire_type == 2)
					return parse_record_name (reader.read_bytes ());
				reader.skip (wire_type);
			}
			return "";
		}

		// A message whose field 1 is the only value of interest (a string).
		private static string first_string (uint8[] data) throws Efni.Error {
			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				if (reader.read_field (out wire_type) == 1 && wire_type == 2)
					return reader.read_string ();
				reader.skip (wire_type);
			}
			return "";
		}
	}
}
