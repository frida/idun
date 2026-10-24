using Efni;

namespace Idun {
	/**
	 * Decodes the push courier's packed (apns-pack-v1) notification format: a
	 * stateful, HPACK-style scheme where each attribute's key byte selects both the
	 * field and how its value is carried — inline, or by reference into per-connection
	 * key and value tables that evolve as frames arrive. A decoded notification is a
	 * tree of dictionaries, arrays and scalars, the FaceTime payload among them.
	 */
	public sealed class CourierPacked : Object {
		private Gee.ArrayList<string> keys = new Gee.ArrayList<string> ();
		private Gee.ArrayList<Variant> values = new Gee.ArrayList<Variant> ();

		public CourierPacked (Bytes connection_token) {
			values.add (new Variant.from_bytes (new VariantType ("ay"), connection_token, true));
		}

		public Variant decode_notification (Bytes frame) throws Efni.Error {
			var cursor = new Cursor (frame.get_data ());
			var fields = new HashTable<string, Variant> (str_hash, str_equal);
			while (!cursor.at_end ()) {
				uint8 head = cursor.read_byte ();
				uint disp = (head >> 4) & 3;
				string name;
				if (disp == 0) {
					name = field_name (cursor.resume_integer (head, 4));
				} else if (disp == 1) {
					name = cursor.read_string (cursor.resume_integer (head, 4) + 1);
					keys.add (name);
				} else {
					name = keys[key_index (cursor.resume_integer (head, 5))];
				}
				fields[name] = read_value (cursor, head >> 6);
			}

			var builder = new VariantBuilder (new VariantType ("a{sv}"));
			fields.foreach ((name, value) => builder.add ("{sv}", name, value));
			return builder.end ();
		}

		private Variant read_value (Cursor cursor, uint rep) throws Efni.Error {
			if (rep == 2)
				return values[value_index (cursor.read_integer (8))];

			Variant value = read_literal (cursor, cursor.read_byte ());
			if (rep == 1)
				values.add (value);
			return value;
		}

		private Variant read_literal (Cursor cursor, uint8 tag) throws Efni.Error {
			if (tag < 0x40)
				return bytes_variant (cursor.read_bytes (cursor.resume_integer (tag, 6)));
			if (tag < 0x60)
				return new Variant.string (cursor.read_string (cursor.resume_integer (tag, 5)));
			if (tag >= 0x80 && tag < 0xa0)
				return new Variant.int64 (tag & 0x1f);
			if (tag >= 0xa0 && tag < 0xc0)
				return new Variant.int64 (read_scalar_integer (cursor, tag));
			if (tag >= 0xc0 && tag < 0xd0)
				return read_dictionary (cursor, cursor.resume_integer (tag, 4));
			if (tag >= 0xd0 && tag < 0xe0)
				return read_array (cursor, cursor.resume_integer (tag, 4));
			if (tag == 0xe0)
				return new Variant.boolean (false);
			if (tag == 0xe1)
				return new Variant.boolean (true);
			throw new Efni.Error.PROTOCOL ("Unknown courier value tag 0x%02x", tag);
		}

		private Variant read_dictionary (Cursor cursor, uint count) throws Efni.Error {
			var builder = new VariantBuilder (new VariantType ("a{sv}"));
			for (uint i = 0; i != count; i++) {
				uint rep;
				string name = read_key (cursor, out rep);
				builder.add ("{sv}", name, read_value (cursor, rep));
			}
			return builder.end ();
		}

		private Variant read_array (Cursor cursor, uint count) throws Efni.Error {
			var builder = new VariantBuilder (new VariantType ("av"));
			for (uint i = 0; i != count; i++)
				builder.add ("v", read_literal (cursor, cursor.read_byte ()));
			return builder.end ();
		}

		private string read_key (Cursor cursor, out uint rep) throws Efni.Error {
			uint8 head = cursor.read_byte ();
			rep = head >> 6;
			uint disp = (head >> 4) & 3;
			if (disp == 1) {
				string name = cursor.read_string (cursor.resume_integer (head, 4) + 1);
				keys.add (name);
				return name;
			}
			uint index = (disp == 0) ? cursor.resume_integer (head, 4) : cursor.resume_integer (head, 5);
			return keys[key_index (index)];
		}

		private static int64 read_scalar_integer (Cursor cursor, uint8 tag) throws Efni.Error {
			uint length = (tag & 7) + 1;
			uint64 magnitude = 0;
			foreach (uint8 b in cursor.read_bytes (length))
				magnitude = (magnitude << 8) | b;
			if ((tag & 0x08) != 0) {
				uint64 modulus = (length == 8) ? 0 : ((uint64) 1 << (length * 8));
				return (int64) (modulus - magnitude);
			}
			return (int64) magnitude;
		}

		private int value_index (uint distance) throws Efni.Error {
			int index = values.size - 1 - (int) distance;
			if (index < 0)
				throw new Efni.Error.PROTOCOL ("Courier value reference out of range");
			return index;
		}

		private int key_index (uint distance) throws Efni.Error {
			int index = keys.size - 1 - (int) distance;
			if (index < 0)
				throw new Efni.Error.PROTOCOL ("Courier key reference out of range");
			return index;
		}

		private static Variant bytes_variant (uint8[] data) {
			return new Variant.from_bytes (new VariantType ("ay"), new Bytes (data), true);
		}

		private static string field_name (uint index) {
			switch (index) {
				case 1: return "token";
				case 2: return "topic-hash";
				case 3: return "payload";
				case 4: return "message-id";
				case 5: return "message-expiry";
				case 6: return "message-timestamp";
				case 9: return "storage-flags";
				case 13: return "priority";
				case 15: return "base-token";
				default: return "field-%u".printf (index);
			}
		}
	}

	private sealed class Cursor {
		private unowned uint8[] data;
		private uint offset;

		public Cursor (uint8[] data) {
			this.data = data;
			this.offset = 0;
		}

		public bool at_end () {
			return offset >= data.length;
		}

		public uint8 read_byte () throws Efni.Error {
			if (offset >= data.length)
				throw new Efni.Error.PROTOCOL ("Courier frame truncated");
			return data[offset++];
		}

		public uint8[] read_bytes (uint length) throws Efni.Error {
			if (offset + length > data.length)
				throw new Efni.Error.PROTOCOL ("Courier frame truncated");
			uint8[] slice = data[offset:offset + length];
			offset += length;
			return slice;
		}

		public string read_string (uint length) throws Efni.Error {
			uint8[] raw = read_bytes (length);
			var buffer = new uint8[length + 1];
			Memory.copy (buffer, raw, length);
			return (string) buffer;
		}

		public uint read_integer (uint prefix_bits) throws Efni.Error {
			return resume_integer (read_byte (), prefix_bits);
		}

		public uint resume_integer (uint8 first, uint prefix_bits) throws Efni.Error {
			uint mask = (1u << prefix_bits) - 1;
			uint value = first & mask;
			if (value < mask)
				return value;
			uint shift = 0;
			while (true) {
				uint8 b = read_byte ();
				value += (uint) (b & 0x7f) << shift;
				shift += 7;
				if ((b & 0x80) == 0)
					break;
			}
			return value;
		}
	}
}
