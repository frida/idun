using Efni;

namespace Idun {
	public enum DTXMessageType {
		OK,
		DATA,
		DISPATCH,
		OBJECT,
		ERROR,
		BARRIER,
		PRIMITIVE,
		COMPRESSED,
		PROXIED_MESSAGE,
	}

	public struct DTXMessage {
		public DTXMessageType type;
		public uint32 identifier;
		public uint32 conversation_index;
		public int32 channel_code;
		public DTXMessageTransportFlags transport_flags;
		public unowned uint8[] aux_data;
		public unowned uint8[] payload_data;
	}

	[Flags]
	public enum DTXMessageTransportFlags {
		NONE          = 0,
		EXPECTS_REPLY = (1 << 0),
	}

	public class DTXArgumentList {
		public Value[] elements;

		private DTXArgumentList (owned Value[] elements) {
			this.elements = (owned) elements;
		}

		public static DTXArgumentList parse (uint8[] data) throws Efni.Error {
			var elements = new Value[0];

			var reader = new PrimitiveReader (data);

			reader.skip (PRIMITIVE_DICTIONARY_HEADER_SIZE);

			while (reader.available_bytes != 0) {
				PrimitiveType type;

				type = (PrimitiveType) reader.read_uint32 ();
				if (type != INDEX)
					throw new Efni.Error.PROTOCOL ("Unsupported primitive dictionary key type");

				type = (PrimitiveType) reader.read_uint32 ();
				switch (type) {
					case STRING: {
						size_t size = reader.read_uint32 ();
						string val = reader.read_string (size);

						var gval = Value (typeof (string));
						gval.take_string ((owned) val);
						elements += (owned) gval;

						break;
					}
					case BUFFER: {
						size_t size = reader.read_uint32 ();
						if (size == 0) {
							var gval = Value (typeof (NSObject));
							elements += (owned) gval;
							break;
						}

						unowned uint8[] buf = reader.read_byte_array (size);

						NSObject? obj = NSKeyedArchive.decode (buf);
						if (obj != null) {
							var gval = Value (Type.from_instance (obj));
							gval.set_instance (obj);
							elements += (owned) gval;
						} else {
							var gval = Value (typeof (NSObject));
							elements += (owned) gval;
						}

						break;
					}
					case INT32: {
						int32 val = reader.read_int32 ();

						var gval = Value (typeof (int));
						gval.set_int (val);
						elements += (owned) gval;

						break;
					}
					case INT64: {
						int64 val = reader.read_int64 ();

						var gval = Value (typeof (int64));
						gval.set_int64 (val);
						elements += (owned) gval;

						break;
					}
					case DOUBLE: {
						double val = reader.read_double ();

						var gval = Value (typeof (double));
						gval.set_double (val);
						elements += (owned) gval;

						break;
					}
					default:
						throw new Efni.Error.PROTOCOL ("Unsupported primitive dictionary value type");
				}
			}

			return new DTXArgumentList ((owned) elements);
		}
	}

	public sealed class DTXArgumentListBuilder {
		private PrimitiveBuilder blob = new PrimitiveBuilder ();

		public DTXArgumentListBuilder () {
			blob.seek (PRIMITIVE_DICTIONARY_HEADER_SIZE);
		}

		public unowned DTXArgumentListBuilder append_string (string str) {
			begin_entry (STRING)
				.append_uint32 (str.length)
				.append_string (str);
			return this;
		}

		public unowned DTXArgumentListBuilder append_object (NSObject? obj) {
			var buf = NSKeyedArchive.encode (obj);
			begin_entry (BUFFER)
				.append_uint32 (buf.length)
				.append_byte_array (buf);
			return this;
		}

		public unowned DTXArgumentListBuilder append_int32 (int32 val) {
			begin_entry (INT32)
				.append_int32 (val);
			return this;
		}

		public unowned DTXArgumentListBuilder append_int64 (int64 val) {
			begin_entry (INT64)
				.append_int64 (val);
			return this;
		}

		public unowned DTXArgumentListBuilder append_double (double val) {
			begin_entry (DOUBLE)
				.append_double (val);
			return this;
		}

		private unowned PrimitiveBuilder begin_entry (PrimitiveType type) {
			return blob
				.append_uint32 (PrimitiveType.INDEX)
				.append_uint32 (type);
		}

		public Bytes build () {
			size_t size = blob.offset - PRIMITIVE_DICTIONARY_HEADER_SIZE;
			return blob.seek (0)
				.append_uint64 (size)
				.append_uint64 (size)
				.build ();
		}
	}

	private enum PrimitiveType {
		STRING = 1,
		BUFFER = 2,
		INT32 = 3,
		INT64 = 6,
		DOUBLE = 9,
		INDEX = 10
	}

	private const size_t PRIMITIVE_DICTIONARY_HEADER_SIZE = 16;

	private sealed class PrimitiveReader {
		public size_t available_bytes {
			get {
				return end - cursor;
			}
		}

		private uint8 * cursor;
		private uint8 * end;

		public PrimitiveReader (uint8[] data) {
			cursor = (uint8 *) data;
			end = cursor + data.length;
		}

		public void skip (size_t n) throws Efni.Error {
			check_available (n);
			cursor += n;
		}

		public int32 read_int32 () throws Efni.Error {
			const size_t n = sizeof (int32);
			check_available (n);

			int32 val = int32.from_little_endian (*((int32 *) cursor));
			cursor += n;

			return val;
		}

		public uint32 read_uint32 () throws Efni.Error {
			const size_t n = sizeof (uint32);
			check_available (n);

			uint32 val = uint32.from_little_endian (*((uint32 *) cursor));
			cursor += n;

			return val;
		}

		public int64 read_int64 () throws Efni.Error {
			const size_t n = sizeof (int64);
			check_available (n);

			int64 val = int64.from_little_endian (*((int64 *) cursor));
			cursor += n;

			return val;
		}

		public uint64 read_uint64 () throws Efni.Error {
			const size_t n = sizeof (uint64);
			check_available (n);

			uint64 val = uint64.from_little_endian (*((uint64 *) cursor));
			cursor += n;

			return val;
		}

		public double read_double () throws Efni.Error {
			uint64 bits = read_uint64 ();
			return *((double *) &bits);
		}

		public unowned uint8[] read_byte_array (size_t n) throws Efni.Error {
			check_available (n);

			unowned uint8[] arr = ((uint8[]) cursor)[0:n];
			cursor += n;

			return arr;
		}

		public string read_string (size_t size) throws Efni.Error {
			check_available (size);

			unowned string data = (string) cursor;
			string str = data.substring (0, (long) size);
			cursor += size;

			return str;
		}

		private void check_available (size_t n) throws Efni.Error {
			if (cursor + n > end)
				throw new Efni.Error.PROTOCOL ("Invalid dictionary");
		}
	}

	private sealed class PrimitiveBuilder {
		public size_t offset {
			get {
				return cursor;
			}
		}

		private ByteArray buffer = new ByteArray.sized (64);
		private size_t cursor = 0;

		public unowned PrimitiveBuilder seek (size_t offset) {
			if (buffer.len < offset) {
				size_t n = offset - buffer.len;
				Memory.set (get_pointer (offset - n, n), 0, n);
			}
			cursor = offset;
			return this;
		}

		public unowned PrimitiveBuilder append_int32 (int32 val) {
			*((int32 *) get_pointer (cursor, sizeof (int32))) = val.to_little_endian ();
			cursor += (uint) sizeof (int32);
			return this;
		}

		public unowned PrimitiveBuilder append_uint32 (uint32 val) {
			*((uint32 *) get_pointer (cursor, sizeof (uint32))) = val.to_little_endian ();
			cursor += (uint) sizeof (uint32);
			return this;
		}

		public unowned PrimitiveBuilder append_int64 (int64 val) {
			*((int64 *) get_pointer (cursor, sizeof (int64))) = val.to_little_endian ();
			cursor += (uint) sizeof (int64);
			return this;
		}

		public unowned PrimitiveBuilder append_uint64 (uint64 val) {
			*((uint64 *) get_pointer (cursor, sizeof (uint64))) = val.to_little_endian ();
			cursor += (uint) sizeof (uint64);
			return this;
		}

		public unowned PrimitiveBuilder append_double (double val) {
			uint64 raw_val = *((uint64 *) &val);
			*((uint64 *) get_pointer (cursor, sizeof (uint64))) = raw_val.to_little_endian ();
			cursor += (uint) sizeof (uint64);
			return this;
		}

		public unowned PrimitiveBuilder append_byte_array (uint8[] array) {
			uint size = array.length;
			Memory.copy (get_pointer (cursor, size), array, size);
			cursor += size;
			return this;
		}

		public unowned PrimitiveBuilder append_string (string str) {
			uint size = str.length;
			Memory.copy (get_pointer (cursor, size), str, size);
			cursor += size;
			return this;
		}

		private uint8 * get_pointer (size_t offset, size_t n) {
			size_t minimum_size = offset + n;
			if (buffer.len < minimum_size)
				buffer.set_size ((uint) minimum_size);

			return (uint8 *) buffer.data + offset;
		}

		public Bytes build () {
			return ByteArray.free_to_bytes ((owned) buffer);
		}
	}
}
