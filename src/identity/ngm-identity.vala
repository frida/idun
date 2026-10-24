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

		private NgmIdentity (Bytes signing_key, Bytes prekey_key, Bytes kem_public, Bytes kem_secret) {
			Object (signing_key: signing_key, prekey_key: prekey_key, kem_public: kem_public,
				kem_secret: kem_secret);
		}

		public static NgmIdentity generate () {
			var pk = new uint8[Kyber.PUBLIC_KEY_BYTES];
			var sk = new uint8[Kyber.SECRET_KEY_BYTES];
			Kyber.keypair (pk, sk);
			return new NgmIdentity (export_private_key (new OpenSSL.Envelope.Key.generate_ec ("P-256")),
				export_private_key (new OpenSSL.Envelope.Key.generate_ec ("P-256")),
				new Bytes (pk), new Bytes (sk));
		}

		public uint8[] signing_public_point () {
			return public_point (load_private_key (signing_key));
		}

		public uint8[] prekey_public_point () {
			return public_point (load_private_key (prekey_key));
		}

		public uint8[] kem_public_key () {
			return kem_public.get_data ();
		}

		public uint8[] registration_signature (double timestamp, uint32 tetra_version) {
			var data = new ByteArray ();
			data.append ("com.apple.Tetra.Registration".data);
			data.append (kem_public_key ());
			data.append (prekey_public_point ());
			data.append (little_endian_double (timestamp));
			data.append (little_endian_uint32 (tetra_version));
			return sign (data.data);
		}

		public uint8[] prekey_signature (double timestamp) {
			var data = new ByteArray ();
			data.append ("NGMPrekeySignature".data);
			data.append (prekey_public_point ());
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
