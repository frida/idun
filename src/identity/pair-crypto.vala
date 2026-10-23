using Efni;

namespace Idun {
	/**
	 * The pair encryption that wraps FaceTime call signaling: a message is sealed to
	 * the peer's RSA key under a one-time AES-CTR key and signed with our EC identity
	 * key, and an incoming message is verified against the peer's EC key and opened
	 * with our own RSA key. Peers are named by the identity key blob they advertised
	 * when they registered.
	 */
	public sealed class PairCrypto : Object {
		public MessageIdentity identity {
			get;
			construct;
		}

		private const int SHA1_LENGTH = 20;
		private const int AES_KEY_LENGTH = 16;

		private const uint8[] EC_P256_SPKI_PREFIX = {
			0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
			0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
		};

		public PairCrypto (MessageIdentity identity) {
			Object (identity: identity);
		}

		public Bytes encrypt (Bytes peer_public_key, uint8[] plaintext) throws Efni.Error {
			uint8[] ec_point, rsa_public;
			parse_public_key (peer_public_key, out ec_point, out rsa_public);
			OpenSSL.Envelope.Key recipient = load_rsa_public_key (rsa_public);

			var aes_key = new uint8[AES_KEY_LENGTH];
			OpenSSL.Rng.generate (aes_key);
			uint8[] cipher = aes_ctr (aes_key, plaintext);

			int head = recipient.size () - 2 * SHA1_LENGTH - 2 - AES_KEY_LENGTH;
			int split = int.min (head, cipher.length);

			var sealed_input = new ByteArray ();
			sealed_input.append (aes_key);
			sealed_input.append (cipher[0:split]);

			var body = new ByteArray ();
			body.append (rsa_oaep_encrypt (recipient, sealed_input.data));
			body.append (cipher[split:cipher.length]);

			uint8[] signature = ecdsa_sha1_sign (load_private_key (identity.signing_key), body.data);
			return assemble (body.data, signature);
		}

		public uint8[] decrypt (Bytes peer_public_key, Bytes payload) throws Efni.Error {
			uint8[] raw = payload.get_data ();
			if (raw.length < 4 || raw[0] != 0x02)
				throw new Efni.Error.PROTOCOL ("Unexpected pair-encrypted payload");

			int body_length = (raw[1] << 8) | raw[2];
			int signature_offset = 3 + body_length;
			if (signature_offset >= raw.length)
				throw new Efni.Error.PROTOCOL ("Truncated pair-encrypted payload");
			int signature_length = raw[signature_offset];
			if (signature_offset + 1 + signature_length > raw.length)
				throw new Efni.Error.PROTOCOL ("Truncated pair-encrypted signature");

			uint8[] body = raw[3:signature_offset];
			uint8[] signature = raw[signature_offset + 1:signature_offset + 1 + signature_length];

			uint8[] ec_point, rsa_public;
			parse_public_key (peer_public_key, out ec_point, out rsa_public);
			if (!ecdsa_sha1_verify (load_ec_public_key (ec_point), body, signature))
				throw new Efni.Error.PROTOCOL ("Pair-encrypted payload failed signature verification");

			OpenSSL.Envelope.Key own = load_private_key (identity.encryption_key);
			int modulus = own.size ();
			uint8[] opened = rsa_oaep_decrypt (own, body[0:modulus]);

			var cipher = new ByteArray ();
			cipher.append (opened[AES_KEY_LENGTH:opened.length]);
			cipher.append (body[modulus:body.length]);
			return aes_ctr (opened[0:AES_KEY_LENGTH], cipher.data);
		}

		private static Bytes assemble (uint8[] body, uint8[] signature) {
			var payload = new ByteArray ();
			payload.append ({ 0x02, (uint8) (body.length >> 8), (uint8) (body.length & 0xff) });
			payload.append (body);
			payload.append ({ (uint8) signature.length });
			payload.append (signature);
			return new Bytes (payload.data);
		}

		private static void parse_public_key (Bytes blob, out uint8[] ec_point, out uint8[] rsa_public)
				throws Efni.Error {
			uint8[] data = blob.get_data ();
			int pos = 0;
			expect_tag (data, ref pos, 0x30);
			read_der_length (data, ref pos);
			ec_point = read_tagged_key (data, ref pos, 0x81);
			rsa_public = read_tagged_key (data, ref pos, 0x82);
		}

		private static uint8[] read_tagged_key (uint8[] data, ref int pos, uint8 tag) throws Efni.Error {
			expect_tag (data, ref pos, tag);
			int length = read_der_length (data, ref pos);
			int start = pos + 2;
			int end = pos + length;
			if (start > data.length || end > data.length)
				throw new Efni.Error.PROTOCOL ("Malformed identity key");
			pos = end;
			return data[start:end];
		}

		private static void expect_tag (uint8[] data, ref int pos, uint8 tag) throws Efni.Error {
			if (pos >= data.length || data[pos] != tag)
				throw new Efni.Error.PROTOCOL ("Malformed identity key");
			pos++;
		}

		private static int read_der_length (uint8[] data, ref int pos) {
			int first = data[pos++];
			if (first < 0x80)
				return first;
			int count = first & 0x7f;
			int length = 0;
			for (int i = 0; i != count; i++)
				length = (length << 8) | data[pos++];
			return length;
		}

		private static uint8[] rsa_oaep_encrypt (OpenSSL.Envelope.Key key, uint8[] plaintext) throws Efni.Error {
			var ctx = new OpenSSL.Envelope.KeyContext.for_key (key);
			ctx.encrypt_init ();
			ctx.set_rsa_padding (OpenSSL.Rsa.PKCS1_OAEP_PADDING);
			ctx.set_rsa_oaep_md (OpenSSL.Envelope.MessageDigest.fetch (null, "SHA1"));

			size_t length = 0;
			ctx.encrypt (null, ref length, plaintext);
			var output = new uint8[length];
			if (ctx.encrypt (output, ref length, plaintext) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to seal the pair-encrypted payload");
			output.length = (int) length;
			return output;
		}

		private static uint8[] rsa_oaep_decrypt (OpenSSL.Envelope.Key key, uint8[] ciphertext) throws Efni.Error {
			var ctx = new OpenSSL.Envelope.KeyContext.for_key (key);
			ctx.decrypt_init ();
			ctx.set_rsa_padding (OpenSSL.Rsa.PKCS1_OAEP_PADDING);
			ctx.set_rsa_oaep_md (OpenSSL.Envelope.MessageDigest.fetch (null, "SHA1"));

			size_t length = 0;
			ctx.decrypt (null, ref length, ciphertext);
			var output = new uint8[length];
			if (ctx.decrypt (output, ref length, ciphertext) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to open the pair-encrypted payload");
			output.length = (int) length;
			return output;
		}

		private static uint8[] aes_ctr (uint8[] key, uint8[] data) throws Efni.Error {
			var iv = new uint8[16];
			iv[15] = 0x01;

			var cipher = OpenSSL.Envelope.Cipher.fetch (null, "AES-128-CTR");
			var ctx = new OpenSSL.Envelope.CipherContext ();
			if (ctx.decrypt_init (cipher, key, iv) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to initialize AES-CTR");

			var output = new uint8[data.length + 16];
			int produced = 0;
			ctx.decrypt_update (output, ref produced, data);
			int total = produced;
			ctx.decrypt_final ((uint8[]) ((uint8 *) output + total), ref produced);
			total += produced;
			return output[0:total];
		}

		private static uint8[] ecdsa_sha1_sign (OpenSSL.Envelope.Key key, uint8[] data) throws Efni.Error {
			var ctx = new OpenSSL.Envelope.MessageDigestContext ();
			ctx.digest_sign_init (null, OpenSSL.Envelope.MessageDigest.fetch (null, "SHA1"), null, key);

			size_t length = 0;
			ctx.digest_sign (null, ref length, data);
			var signature = new uint8[length];
			ctx.digest_sign (signature, ref length, data);
			signature.length = (int) length;
			return signature;
		}

		private static bool ecdsa_sha1_verify (OpenSSL.Envelope.Key key, uint8[] data, uint8[] signature) {
			var ctx = new OpenSSL.Envelope.MessageDigestContext ();
			ctx.digest_verify_init (null, OpenSSL.Envelope.MessageDigest.fetch (null, "SHA1"), null, key);
			return ctx.digest_verify (signature, data) == 1;
		}

		private static OpenSSL.Envelope.Key load_private_key (Bytes pem) {
			var source = new OpenSSL.BasicIO.from_static_memory_buffer (pem.get_data ());
			return new OpenSSL.Envelope.Key.from_private_key_pem (source);
		}

		private static OpenSSL.Envelope.Key load_rsa_public_key (uint8[] der) {
			uint8* cursor = der;
			return new OpenSSL.Envelope.Key.from_legacy_public_der (OpenSSL.Envelope.KeyType.RSA, null, &cursor,
				der.length);
		}

		private static OpenSSL.Envelope.Key load_ec_public_key (uint8[] point) {
			var spki = new ByteArray ();
			spki.append (EC_P256_SPKI_PREFIX);
			spki.append (point);

			var source = new OpenSSL.BasicIO.from_static_memory_buffer (spki.data);
			return new OpenSSL.Envelope.Key.from_der (source);
		}
	}
}
