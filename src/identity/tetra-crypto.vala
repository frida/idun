using Efni;
using OpenSSL;
using OpenSSL.Envelope;

namespace Idun {
	/**
	 * The symmetric primitives of the pair-tetra ratchet: the stream cipher that seals
	 * the message body, the HKDF the key schedule is built on, and the derivations that
	 * advance a ratchet one step and turn a message key into the cipher's keying.
	 */
	public sealed class TetraCrypto {
		private const string RATCHET_BASE = "Tetra-v1.0-SymmetricRatchet-";
		private const string CHAIN_KEY_INFO = RATCHET_BASE + "ChainKeyDerivation";
		private const string MESSAGE_KEY_INFO = RATCHET_BASE + "MessageKeyDerivation";
		private const string SENDER_AUTH_INFO = "Tetra-v1.0-SymmetricLayer-AES-CTR-Keying";

		private const int MESSAGE_KEY_LENGTH = 32;
		private const int CTR_IV_LENGTH = 16;

		public static uint8[] aes_256_ctr (uint8[] key, uint8[] iv, uint8[] data) throws Efni.Error {
			var cipher = Cipher.fetch (null, "AES-256-CTR");
			var ctx = new CipherContext ();
			if (ctx.decrypt_init (cipher, key, iv) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to initialize AES-256-CTR");

			var output = new uint8[data.length + CTR_IV_LENGTH];
			int produced = 0;
			ctx.decrypt_update (output, ref produced, data);
			int total = produced;
			ctx.decrypt_final ((uint8[]) ((uint8 *) output + total), ref produced);
			total += produced;
			return output[0 : total];
		}

		/**
		 * HKDF-Expand only: the input is already a pseudo-random key, so no extract step
		 * runs. This is how the symmetric ratchet and the sender-authentication keying
		 * are derived.
		 */
		private const int HKDF_MODE_EXTRACT_AND_EXPAND = 0;
		private const int HKDF_MODE_EXPAND_ONLY = 2;

		public static uint8[] hkdf_expand (string digest, uint8[] prk, uint8[] info, int length)
				throws Efni.Error {
			return hkdf (digest, HKDF_MODE_EXPAND_ONLY, prk, {}, info, length);
		}

		/**
		 * HKDF extract-and-expand: salt and input key material are extracted into a
		 * pseudo-random key which is then expanded. This is the root/Diffie-Hellman
		 * ratchet step, salted with the previous root key.
		 */
		public static uint8[] hkdf_extract_and_expand (string digest, uint8[] ikm, uint8[] salt,
				uint8[] info, int length) throws Efni.Error {
			return hkdf (digest, HKDF_MODE_EXTRACT_AND_EXPAND, ikm, salt, info, length);
		}

		public static void derive_sender_authentication (uint8[] message_key, out uint8[] iv,
				out uint8[] key) throws Efni.Error {
			uint8[] keying = hkdf_expand (ShortName.sha384, message_key, SENDER_AUTH_INFO.data,
				CTR_IV_LENGTH + MESSAGE_KEY_LENGTH);
			iv = keying[0 : CTR_IV_LENGTH];
			key = keying[CTR_IV_LENGTH : CTR_IV_LENGTH + MESSAGE_KEY_LENGTH];
		}

		public static uint8[] advance_chain_key (uint8[] chain_key) throws Efni.Error {
			return hkdf_expand (ShortName.sha384, chain_key, CHAIN_KEY_INFO.data, MESSAGE_KEY_LENGTH);
		}

		public static uint8[] derive_message_key (uint8[] chain_key) throws Efni.Error {
			return hkdf_expand (ShortName.sha384, chain_key, MESSAGE_KEY_INFO.data, MESSAGE_KEY_LENGTH);
		}

		private static uint8[] hkdf (string digest, int mode, uint8[] key, uint8[] salt,
				uint8[] info, int length) throws Efni.Error {
			var kdf = KeyDerivationFunction.fetch (null, KeyDerivationAlgorithm.HKDF);
			var ctx = new KeyDerivationContext (kdf);

			int mode_value = mode;
			size_t return_size = ParamReturnSize.UNMODIFIED;
			var output = new uint8[length];
			int result;

			if (mode == HKDF_MODE_EXPAND_ONLY) {
				var mode_bytes = to_bytes (&mode_value);
				Param params[] = {
					{ KeyDerivationParameter.MODE, INTEGER, mode_bytes, return_size },
					{ KeyDerivationParameter.DIGEST, UTF8_STRING, digest.data, return_size },
					{ KeyDerivationParameter.KEY, OCTET_STRING, key, return_size },
					{ KeyDerivationParameter.INFO, OCTET_STRING, info, return_size },
					{ null, INTEGER, null, return_size },
				};
				result = ctx.derive (output, params);
			} else {
				Param params[] = {
					{ KeyDerivationParameter.DIGEST, UTF8_STRING, digest.data, return_size },
					{ KeyDerivationParameter.KEY, OCTET_STRING, key, return_size },
					{ KeyDerivationParameter.SALT, OCTET_STRING, salt, return_size },
					{ KeyDerivationParameter.INFO, OCTET_STRING, info, return_size },
					{ null, INTEGER, null, return_size },
				};
				result = ctx.derive (output, params);
			}

			if (result != 1)
				throw new Efni.Error.PROTOCOL ("HKDF derivation failed");
			return output;
		}

		private static uint8[] to_bytes (int* value) {
			var bytes = new uint8[sizeof (int)];
			Memory.copy (bytes, value, sizeof (int));
			return bytes;
		}
	}
}
