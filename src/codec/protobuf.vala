using Efni;

namespace Idun {
	public sealed class ProtobufWriter {
		private ByteArray buffer = new ByteArray ();

		public uint8[] data {
			owned get {
				return buffer.data;
			}
		}

		public unowned ProtobufWriter append_varint (int field, uint64 value) {
			write_tag (field, 0);
			write_varint (value);
			return this;
		}

		public unowned ProtobufWriter append_fixed64 (int field, uint64 value) {
			write_tag (field, 1);
			for (int i = 0; i != 8; i++)
				buffer.append ({ (uint8) (value >> (8 * i)) });
			return this;
		}

		public unowned ProtobufWriter append_double (int field, double value) {
			return append_fixed64 (field, *((uint64*) (&value)));
		}

		public unowned ProtobufWriter append_bytes (int field, uint8[] value) {
			write_tag (field, 2);
			write_varint (value.length);
			buffer.append (value);
			return this;
		}

		private void write_tag (int field, uint8 wire_type) {
			write_varint (((uint64) field << 3) | wire_type);
		}

		private void write_varint (uint64 value) {
			do {
				uint8 piece = (uint8) (value & 0x7f);
				value >>= 7;
				if (value != 0)
					piece |= 0x80;
				buffer.append ({ piece });
			} while (value != 0);
		}
	}

	public sealed class ProtobufReader {
		private uint8[] data;
		private int offset;

		public bool has_more {
			get {
				return offset < data.length;
			}
		}

		public ProtobufReader (uint8[] data) {
			this.data = data;
		}

		public int read_field (out uint8 wire_type) throws Efni.Error {
			uint64 tag = read_varint ();
			wire_type = (uint8) (tag & 7);
			return (int) (tag >> 3);
		}

		public uint64 read_varint () throws Efni.Error {
			uint64 value = 0;
			int shift = 0;
			while (true) {
				if (offset == data.length)
					throw new Efni.Error.PROTOCOL ("Truncated protobuf varint");
				uint8 piece = data[offset++];
				value |= (uint64) (piece & 0x7f) << shift;
				if ((piece & 0x80) == 0)
					return value;
				shift += 7;
			}
		}

		public uint64 read_fixed64 () throws Efni.Error {
			if (offset + 8 > data.length)
				throw new Efni.Error.PROTOCOL ("Truncated protobuf fixed64");
			uint64 value = 0;
			for (int i = 0; i != 8; i++)
				value |= (uint64) data[offset++] << (8 * i);
			return value;
		}

		public double read_double () throws Efni.Error {
			uint64 bits = read_fixed64 ();
			return *((double*) (&bits));
		}

		public uint8[] read_bytes () throws Efni.Error {
			int length = (int) read_varint ();
			if (length < 0 || offset + length > data.length)
				throw new Efni.Error.PROTOCOL ("Truncated protobuf bytes");
			uint8[] value = data[offset : offset + length];
			offset += length;
			return value;
		}

		public void skip (uint8 wire_type) throws Efni.Error {
			switch (wire_type) {
				case 0:
					read_varint ();
					break;
				case 1:
					read_fixed64 ();
					break;
				case 2:
					read_bytes ();
					break;
				case 5:
					if (offset + 4 > data.length)
						throw new Efni.Error.PROTOCOL ("Truncated protobuf fixed32");
					offset += 4;
					break;
				default:
					throw new Efni.Error.PROTOCOL ("Unsupported protobuf wire type");
			}
		}
	}
}
