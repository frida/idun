using Efni;

namespace Idun.NgmIdentityTest {
	public void add_tests () {
		GLib.Test.add_func ("/NgmIdentity/serializes-device-identity", serializes_device_identity);
		GLib.Test.add_func ("/NgmIdentity/serializes-device-prekey", serializes_device_prekey);
	}

	private void serializes_device_identity () {
		var identity = NgmIdentity.generate ();

		var bundle = new PrekeyReader (identity.device_identity_data (15));

		assert_true (bundle.read_bytes_field (1).length == 32);
		assert_true (bundle.read_varint_field (2) == 15);
	}

	private void serializes_device_prekey () {
		var identity = NgmIdentity.generate ();

		var prekey = new PrekeyReader (identity.device_prekey_data (1792659144.3164039, 15));

		assert_true (prekey.read_bytes_field (1).length == 32);
		assert_true (prekey.read_bytes_field (2).length == 64);
		prekey.read_fixed64_field (3);
		var tetra = new PrekeyReader (prekey.read_bytes_field (4));
		assert_true (tetra.read_bytes_field (1).length == Kyber.PUBLIC_KEY_BYTES);
		assert_true (tetra.read_bytes_field (2).length == 64);
	}

	private class PrekeyReader {
		private uint8[] data;
		private int offset;

		public PrekeyReader (uint8[] data) {
			this.data = data;
		}

		public uint8[] read_bytes_field (int field) {
			assert_true (data[offset++] == (field << 3 | 2));
			int length = (int) read_varint ();
			uint8[] value = data[offset : offset + length];
			offset += length;
			return value;
		}

		public uint64 read_varint_field (int field) {
			assert_true (data[offset++] == (field << 3 | 0));
			return read_varint ();
		}

		public void read_fixed64_field (int field) {
			assert_true (data[offset++] == (field << 3 | 1));
			offset += 8;
		}

		private uint64 read_varint () {
			uint64 value = 0;
			int shift = 0;
			while ((data[offset] & 0x80) != 0) {
				value |= (uint64) (data[offset++] & 0x7f) << shift;
				shift += 7;
			}
			value |= (uint64) data[offset++] << shift;
			return value;
		}
	}
}
