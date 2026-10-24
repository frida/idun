using Efni;

namespace Idun {
	/**
	 * The device's NGM identity: the post-quantum key material a modern IDS device
	 * publishes so peers running the current protocol can resolve and seal traffic to
	 * it. A P-256 key signs the identity and its prekeys, a P-256 key agreement prekey
	 * carries the classical half of the key exchange, and a Kyber-1024 key carries
	 * the post-quantum half. The public halves are what Idun advertises when it
	 * registers; the private halves open the pair-tetra traffic the identity services
	 * exchange.
	 */
	public sealed class NgmIdentity : Object {
		public Bytes signing_key {
			get;
			construct;
		}

		public Bytes prekey_key {
			get;
			construct;
		}

		public Bytes kem_public {
			get;
			construct;
		}

		public Bytes kem_secret {
			get;
			construct;
		}

		private const int EC_POINT_LENGTH = 65;

		private const uint8[] P256_PRIME = {
			0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		};

		private NgmIdentity (Bytes signing_key, Bytes prekey_key, Bytes kem_public, Bytes kem_secret) {
			Object (signing_key: signing_key, prekey_key: prekey_key, kem_public: kem_public,
				kem_secret: kem_secret);
		}

		public static NgmIdentity generate () {
			var pk = new uint8[Kyber.PUBLIC_KEY_BYTES];
			var sk = new uint8[Kyber.SECRET_KEY_BYTES];
			Kyber.keypair (pk, sk);
			return new NgmIdentity (export_private_key (generate_compact_key ()),
				export_private_key (generate_compact_key ()),
				new Bytes (pk), new Bytes (sk));
		}

		public uint8[] device_identity_data (uint32 tetra_version) {
			var message = new ByteArray ();
			append_bytes_field (message, 1, signing_compact_key ());
			append_varint_field (message, 2, tetra_version);
			return message.data;
		}

		public uint8[] device_prekey_data (double timestamp, uint32 tetra_version) {
			var tetra = new ByteArray ();
			append_bytes_field (tetra, 1, kem_public_key ());
			append_bytes_field (tetra, 2, registration_signature (timestamp, tetra_version));

			var message = new ByteArray ();
			append_bytes_field (message, 1, prekey_compact_key ());
			append_bytes_field (message, 2, prekey_signature (timestamp));
			append_double_field (message, 3, timestamp);
			append_bytes_field (message, 4, tetra.data);
			return message.data;
		}

		public uint8[] signing_public_point () {
			return public_point (load_private_key (signing_key));
		}

		public uint8[] signing_compact_key () {
			return signing_public_point ()[1 : 33];
		}

		public uint8[] prekey_public_point () {
			return public_point (load_private_key (prekey_key));
		}

		public uint8[] prekey_compact_key () {
			return prekey_public_point ()[1 : 33];
		}

		public uint8[] kem_public_key () {
			return kem_public.get_data ();
		}

		public uint8[] registration_signature (double timestamp, uint32 tetra_version) {
			var data = new ByteArray ();
			data.append ("com.apple.Tetra.Registration".data);
			data.append (kem_public_key ());
			data.append (prekey_compact_key ());
			data.append (little_endian_double (timestamp));
			data.append (little_endian_uint32 (tetra_version));
			return sign (data.data);
		}

		public uint8[] prekey_signature (double timestamp) {
			var data = new ByteArray ();
			data.append ("NGMPrekeySignature".data);
			data.append (prekey_compact_key ());
			data.append (little_endian_double (timestamp));
			return sign (data.data);
		}

		private uint8[] sign (uint8[] data) {
			OpenSSL.Envelope.Key key = load_private_key (signing_key);
			var ctx = new OpenSSL.Envelope.MessageDigestContext ();
			ctx.digest_sign_init (null, OpenSSL.Envelope.MessageDigest.fetch (null, "SHA256"), null, key);
			size_t length = 0;
			ctx.digest_sign (null, ref length, data);
			var der = new uint8[length];
			ctx.digest_sign (der, ref length, data);
			der.length = (int) length;
			return der_signature_to_raw (der);
		}

		private static uint8[] der_signature_to_raw (uint8[] der) {
			int pos = 2;
			var raw = new uint8[64];
			for (int component = 0; component != 2; component++) {
				pos++;
				int length = der[pos++];
				int start = pos + int.max (0, length - 32);
				int offset = 32 * component + int.max (0, 32 - length);
				Memory.copy ((uint8*) raw + offset, (uint8*) der + start, pos + length - start);
				pos += length;
			}
			return raw;
		}

		private static OpenSSL.Envelope.Key generate_compact_key () {
			while (true) {
				var key = new OpenSSL.Envelope.Key.generate_ec ("P-256");
				uint8[] y = public_point (key)[33 : 65];
				if (compare_big_endian (y, subtract_big_endian (P256_PRIME, y)) <= 0)
					return key;
			}
		}

		private static int compare_big_endian (uint8[] a, uint8[] b) {
			for (int i = 0; i != a.length; i++) {
				if (a[i] != b[i])
					return (a[i] < b[i]) ? -1 : 1;
			}
			return 0;
		}

		private static uint8[] subtract_big_endian (uint8[] a, uint8[] b) {
			var result = new uint8[a.length];
			int borrow = 0;
			for (int i = a.length - 1; i >= 0; i--) {
				int diff = a[i] - b[i] - borrow;
				borrow = (diff < 0) ? 1 : 0;
				result[i] = (uint8) (diff + 256 * borrow);
			}
			return result;
		}

		private static void append_bytes_field (ByteArray message, int field, uint8[] value) {
			append_varint (message, ((uint64) field << 3) | 2);
			append_varint (message, value.length);
			message.append (value);
		}

		private static void append_varint_field (ByteArray message, int field, uint64 value) {
			append_varint (message, (uint64) field << 3);
			append_varint (message, value);
		}

		private static void append_double_field (ByteArray message, int field, double value) {
			append_varint (message, ((uint64) field << 3) | 1);
			message.append (little_endian_double (value));
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

		private static uint8[] little_endian_double (double value) {
			uint64 bits = *((uint64*) (&value));
			return little_endian (bits, 8);
		}

		private static uint8[] little_endian_uint32 (uint32 value) {
			return little_endian (value, 4);
		}

		private static uint8[] little_endian (uint64 value, int width) {
			var result = new uint8[width];
			for (int i = 0; i != width; i++)
				result[i] = (uint8) (value >> (8 * i));
			return result;
		}

		private static OpenSSL.Envelope.Key load_private_key (Bytes pem) {
			var source = new OpenSSL.BasicIO.from_static_memory_buffer (pem.get_data ());
			return new OpenSSL.Envelope.Key.from_private_key_pem (source);
		}

		private static Bytes export_private_key (OpenSSL.Envelope.Key key) {
			var sink = new OpenSSL.BasicIO (OpenSSL.BasicIOMethod.memory ());
			OpenSSL.Envelope.write_private_key_pem (sink, key);
			unowned uint8[] data;
			long size = sink.get_mem_data (out data);
			data.length = (int) size;
			return new Bytes (data);
		}

		private static uint8[] public_point (OpenSSL.Envelope.Key key) {
			var sink = new OpenSSL.BasicIO (OpenSSL.BasicIOMethod.memory ());
			key.to_der (sink);
			unowned uint8[] data;
			long size = sink.get_mem_data (out data);
			return data[size - EC_POINT_LENGTH : size];
		}
	}
}
