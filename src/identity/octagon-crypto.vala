using Efni;
using OpenSSL;
using OpenSSL.Envelope;

namespace Idun {
	/**
	 * The symmetric and signature primitives Octagon bottles are built from: AES-256-GCM
	 * for the bottle contents, and ECDSA over P-384 with SHA-384 for the escrow and peer
	 * signatures that authenticate a bottle.
	 */
	public sealed class OctagonCrypto {
		private const int GCM_TAG_LENGTH = 16;

		/**
		 * AES-SIV decrypt as CKKS wraps its keys and items (RFC 5297). The wrapped blob is the
		 * 16-byte synthetic IV followed by the ciphertext; each associated-data element is fed in
		 * order before the ciphertext, and the synthetic IV authenticates them all. The key is the
		 * double-length SIV key (64 bytes for AES-256-SIV). Throws if authentication fails.
		 */
		public static uint8[] aes_siv_encrypt (uint8[] key, uint8[] plaintext, Bytes[] associated_data)
				throws Efni.Error {
			string algorithm = (key.length == 64) ? "AES-256-SIV"
				: (key.length == 48) ? "AES-192-SIV" : "AES-128-SIV";
			var ctx = new CipherContext ();
			var cipher = Cipher.fetch (null, algorithm);
			if (cipher == null || ctx.encrypt_init_ex (cipher) != 1 ||
					ctx.encrypt_init_ex (null, null, key) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to initialize AES-SIV");

			int outlen = 0;
			foreach (var aad in associated_data) {
				if (ctx.encrypt_update_aad (null, ref outlen, aad.get_data ()) != 1)
					throw new Efni.Error.PROTOCOL ("AES-SIV rejected associated data");
			}

			var ciphertext = new uint8[plaintext.length];
			if (ctx.encrypt_update (ciphertext, ref outlen, plaintext) != 1)
				throw new Efni.Error.PROTOCOL ("AES-SIV encryption failed");
			int produced = outlen;
			var tail = new uint8[16];
			ctx.encrypt_final (tail, ref outlen);
			var synthetic_iv = new uint8[16];
			if (ctx.ctrl (CipherCtrlType.AEAD_GET_TAG, 16, synthetic_iv) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to read AES-SIV synthetic IV");

			var result = new uint8[16 + produced];
			Memory.copy (result, synthetic_iv, 16);
			Memory.copy ((uint8 *) result + 16, ciphertext, produced);
			return result;
		}

		/**
		 * AES key unwrap (RFC 3394) with the default initial value, as PCS uses to unwrap a key
		 * wrapped under an RFC 6637 key-encryption key.
		 */
		public static uint8[] aes_gcm_encrypt (uint8[] key, uint8[] iv, uint8[] plaintext,
				uint8[] aad, out uint8[] tag) throws Efni.Error {
			string algorithm = (key.length == 16) ? "AES-128-GCM"
				: (key.length == 24) ? "AES-192-GCM" : "AES-256-GCM";

			var ctx = new CipherContext ();
			var cipher = Cipher.fetch (null, algorithm);
			if (cipher == null || ctx.encrypt_init_ex (cipher) != 1 ||
					ctx.ctrl (CipherCtrlType.GCM_SET_IVLEN, iv.length, null) != 1 ||
					ctx.encrypt_init_ex (null, null, key, iv) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to initialize AES-GCM");

			int outlen = 0;
			if (aad.length != 0 && ctx.encrypt_update_aad (null, ref outlen, aad) != 1)
				throw new Efni.Error.PROTOCOL ("AES-GCM rejected associated data");

			var ciphertext = new uint8[plaintext.length];
			if (ctx.encrypt_update (ciphertext, ref outlen, plaintext) != 1)
				throw new Efni.Error.PROTOCOL ("AES-GCM encryption failed");
			int produced = outlen;

			var tail = new uint8[16];
			ctx.encrypt_final (tail, ref outlen);

			tag = new uint8[16];
			if (ctx.ctrl (CipherCtrlType.AEAD_GET_TAG, tag.length, tag) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to read AES-GCM tag");

			ciphertext.length = produced;
			return ciphertext;
		}

		public static uint8[] aes_gcm_decrypt (uint8[] key, uint8[] iv, uint8[] ciphertext,
				uint8[] tag, uint8[] aad) throws Efni.Error {
			string algorithm = (key.length == 16) ? "AES-128-GCM"
				: (key.length == 24) ? "AES-192-GCM" : "AES-256-GCM";

			var ctx = new CipherContext ();
			var cipher = Cipher.fetch (null, algorithm);
			if (cipher == null || ctx.decrypt_init_ex (cipher) != 1 ||
					ctx.ctrl (CipherCtrlType.GCM_SET_IVLEN, iv.length, null) != 1 ||
					ctx.decrypt_init_ex (null, null, key, iv) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to initialize AES-GCM");

			int outlen = 0;
			if (aad.length != 0 && ctx.decrypt_update_aad (null, ref outlen, aad) != 1)
				throw new Efni.Error.PROTOCOL ("AES-GCM rejected associated data");

			var plaintext = new uint8[ciphertext.length];
			if (ctx.decrypt_update (plaintext, ref outlen, ciphertext) != 1)
				throw new Efni.Error.PROTOCOL ("AES-GCM decryption failed");
			int produced = outlen;

			if (ctx.ctrl (CipherCtrlType.GCM_SET_TAG, tag.length, tag) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to set AES-GCM tag");
			var tail = new uint8[16];
			if (ctx.decrypt_final (tail, ref outlen) != 1)
				throw new Efni.Error.PROTOCOL ("AES-GCM authentication failed");

			plaintext.length = produced;
			return plaintext;
		}

		public static uint8[] aes_kw_unwrap (uint8[] kek, uint8[] wrapped) throws Efni.Error {
			string algorithm = (kek.length == 16) ? "AES-128-WRAP"
				: (kek.length == 24) ? "AES-192-WRAP" : "AES-256-WRAP";

			var ctx = new CipherContext ();
			var cipher = Cipher.fetch (null, algorithm);
			if (cipher == null || ctx.decrypt_init_ex (cipher, null, kek, null) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to initialize AES key unwrap");

			var output = new uint8[wrapped.length];
			int outlen = output.length;
			if (ctx.decrypt_update (output, ref outlen, wrapped) != 1)
				throw new Efni.Error.PROTOCOL ("AES key unwrap failed");
			int produced = outlen;

			int final_length = 0;
			var tail = new uint8[16];
			ctx.decrypt_final (tail, ref final_length);

			output.length = produced + final_length;
			return output;
		}

		public static uint8[] aes_siv_decrypt (uint8[] key, uint8[] wrapped, Bytes[] associated_data)
				throws Efni.Error {
			if (wrapped.length < 16)
				throw new Efni.Error.PROTOCOL ("AES-SIV blob is shorter than its synthetic IV");
			string algorithm = (key.length == 64) ? "AES-256-SIV"
				: (key.length == 48) ? "AES-192-SIV" : "AES-128-SIV";
			var ctx = new CipherContext ();
			var cipher = Cipher.fetch (null, algorithm);
			if (cipher == null || ctx.decrypt_init_ex (cipher) != 1 ||
					ctx.decrypt_init_ex (null, null, key) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to initialize AES-SIV");

			var synthetic_iv = wrapped[0 : 16];
			if (ctx.ctrl (CipherCtrlType.AEAD_SET_TAG, 16, synthetic_iv) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to set AES-SIV synthetic IV");

			int outlen = 0;
			foreach (var aad in associated_data) {
				if (ctx.decrypt_update_aad (null, ref outlen, aad.get_data ()) != 1)
					throw new Efni.Error.PROTOCOL ("AES-SIV rejected associated data");
			}

			var ciphertext = wrapped[16 : wrapped.length];
			var plaintext = new uint8[ciphertext.length];
			if (ctx.decrypt_update (plaintext, ref outlen, ciphertext) != 1)
				throw new Efni.Error.PROTOCOL ("AES-SIV decryption failed");
			int produced = outlen;
			var tail = new uint8[16];
			if (ctx.decrypt_final (tail, ref outlen) != 1)
				throw new Efni.Error.PROTOCOL ("AES-SIV authentication failed");
			plaintext.length = produced;
			return plaintext;
		}

		public static uint8[] aes_256_gcm_encrypt (uint8[] key, uint8[] iv, uint8[] plaintext,
				out uint8[] tag) throws Efni.Error {
			var ctx = new CipherContext ();
			var cipher = Cipher.fetch (null, "AES-256-GCM");
			if (ctx.encrypt_init_ex (cipher) != 1 ||
					ctx.ctrl (CipherCtrlType.GCM_SET_IVLEN, iv.length, null) != 1 ||
					ctx.encrypt_init_ex (null, null, key, iv) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to initialize AES-256-GCM encryption");

			var output = new uint8[plaintext.length];
			int produced = 0;
			if (ctx.encrypt_update (output, ref produced, plaintext) != 1)
				throw new Efni.Error.PROTOCOL ("AES-256-GCM encryption failed");
			int total = produced;
			int final_len = 0;
			ctx.encrypt_final ((uint8[]) ((uint8 *) output + total), ref final_len);
			total += final_len;

			tag = new uint8[GCM_TAG_LENGTH];
			ctx.ctrl (CipherCtrlType.GCM_GET_TAG, GCM_TAG_LENGTH, (void *) tag);
			return output[0 : total];
		}

		public static uint8[] aes_256_gcm_decrypt (uint8[] key, uint8[] iv, uint8[] ciphertext,
				uint8[] tag) throws Efni.Error {
			var ctx = new CipherContext ();
			var cipher = Cipher.fetch (null, "AES-256-GCM");
			if (ctx.decrypt_init_ex (cipher) != 1 ||
					ctx.ctrl (CipherCtrlType.GCM_SET_IVLEN, iv.length, null) != 1 ||
					ctx.decrypt_init_ex (null, null, key, iv) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to initialize AES-256-GCM decryption");

			var output = new uint8[ciphertext.length];
			int produced = 0;
			if (ctx.decrypt_update (output, ref produced, ciphertext) != 1)
				throw new Efni.Error.PROTOCOL ("AES-256-GCM decryption failed");
			int total = produced;

			if (ctx.ctrl (CipherCtrlType.GCM_SET_TAG, tag.length, (void *) tag) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to set AES-256-GCM tag");
			int final_len = 0;
			if (ctx.decrypt_final ((uint8[]) ((uint8 *) output + total), ref final_len) != 1)
				throw new Efni.Error.PROTOCOL ("Octagon bottle authentication failed");
			total += final_len;
			return output[0 : total];
		}

		/**
		 * AES-CBC decryption with no implicit padding: the caller strips PKCS#7 padding,
		 * matching the escrow key-vault layers where the trailing bytes are inspected directly.
		 * The key length selects AES-128 or AES-256.
		 */
		public static uint8[] aes_cbc_decrypt (uint8[] key, uint8[] iv, uint8[] ciphertext)
				throws Efni.Error {
			var ctx = new CipherContext ();
			var cipher = Cipher.fetch (null, (key.length == 16) ? "AES-128-CBC" : "AES-256-CBC");
			if (ctx.decrypt_init_ex (cipher, null, key, iv) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to initialize AES-CBC decryption");
			ctx.set_padding (0);

			var output = new uint8[ciphertext.length + 16];
			int produced = 0;
			if (ctx.decrypt_update (output, ref produced, ciphertext) != 1)
				throw new Efni.Error.PROTOCOL ("AES-CBC decryption failed");
			int total = produced;
			int final_len = 0;
			if (ctx.decrypt_final ((uint8[]) ((uint8 *) output + total), ref final_len) != 1)
				throw new Efni.Error.PROTOCOL ("AES-CBC decryption failed");
			total += final_len;

			uint8[] plain = output[0 : total];
			return strip_pkcs7 (plain);
		}

		/**
		 * AES-CBC encryption with PKCS#7 padding, the inverse of {@link aes_cbc_decrypt}; used by
		 * tests that stand in for the escrow proxy to seal records the recovery path then unwraps.
		 */
		public static uint8[] aes_cbc_encrypt (uint8[] key, uint8[] iv, uint8[] plaintext)
				throws Efni.Error {
			var ctx = new CipherContext ();
			var cipher = Cipher.fetch (null, (key.length == 16) ? "AES-128-CBC" : "AES-256-CBC");
			if (ctx.encrypt_init_ex (cipher, null, key, iv) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to initialize AES-CBC encryption");

			var output = new uint8[plaintext.length + 16];
			int produced = 0;
			if (ctx.encrypt_update (output, ref produced, plaintext) != 1)
				throw new Efni.Error.PROTOCOL ("AES-CBC encryption failed");
			int total = produced;
			int final_len = 0;
			if (ctx.encrypt_final ((uint8[]) ((uint8 *) output + total), ref final_len) != 1)
				throw new Efni.Error.PROTOCOL ("AES-CBC encryption failed");
			total += final_len;
			return output[0 : total];
		}

		private static uint8[] strip_pkcs7 (uint8[] data) {
			if (data.length == 0)
				return data;
			int pad = data[data.length - 1];
			if (pad < 1 || pad > 16 || pad > data.length)
				return data;
			for (int i = data.length - pad; i != data.length; i++) {
				if (data[i] != pad)
					return data;
			}
			return data[0 : data.length - pad];
		}

		/**
		 * PBKDF2-HMAC-SHA256, the inner key-derivation the escrow key vault uses to turn the
		 * passcode and the record salt into the AES-128 key that unwraps the escrowed bottle.
		 */
		public static uint8[] pbkdf2_sha256 (uint8[] password, uint8[] salt, int iterations,
				int length) throws Efni.Error {
			var output = new uint8[length];
			if (OpenSSL.pkcs5_pbkdf2_hmac (password, password.length, salt, salt.length, iterations,
					MessageDigest.fetch (null, "SHA256"), length, output) != 1)
				throw new Efni.Error.PROTOCOL ("PBKDF2-HMAC-SHA256 derivation failed");
			return output;
		}

		public static uint8[] sign (Bytes private_key_pem, uint8[] data, string digest = "SHA384")
				throws Efni.Error {
			var ctx = new MessageDigestContext ();
			ctx.digest_sign_init (null, MessageDigest.fetch (null, digest), null,
				load_private_key (private_key_pem));

			size_t length = 0;
			ctx.digest_sign (null, ref length, data);
			var signature = new uint8[length];
			ctx.digest_sign (signature, ref length, data);
			signature.length = (int) length;
			return signature;
		}

		public static bool verify (uint8[] public_key_spki, uint8[] data, uint8[] signature,
				string digest = "SHA384") throws Efni.Error {
			var ctx = new MessageDigestContext ();
			ctx.digest_verify_init (null, MessageDigest.fetch (null, digest), null,
				load_public_key (public_key_spki));
			return ctx.digest_verify (signature, data) == 1;
		}

		private static Key load_private_key (Bytes pem) {
			var source = new OpenSSL.BasicIO.from_static_memory_buffer (pem.get_data ());
			return new Key.from_private_key_pem (source);
		}

		private static Key load_public_key (uint8[] spki_der) {
			var source = new OpenSSL.BasicIO.from_static_memory_buffer (spki_der);
			return new Key.from_der (source);
		}
	}
}
