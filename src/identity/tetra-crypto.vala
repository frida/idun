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
		private const string SYMMETRIC_LAYER_BASE = "Tetra-v1.0-SymmetricLayer-";
		private const string SENDER_AUTH_INFO = SYMMETRIC_LAYER_BASE + "AES-CTR-Keying";
		private const string MESSAGE_KEY_INDICATOR_INFO = SYMMETRIC_LAYER_BASE + "MessageKeyIndicator";
		private const string ROOT_KEY_INFO = "Tetra-v1.0-RootKeyDerivation-";
		private const string MESSAGE_SIGNATURE_DOMAIN = "com.apple.Tetra.MessageSignature";
		private const string NO_RATCHET_SIGNATURE_DOMAIN = "com.apple.TetraNoRatchet.MessageSignature";

		private const int MESSAGE_KEY_LENGTH = 32;
		private const int CTR_IV_LENGTH = 16;
		private const int ROOT_AND_CHAIN_LENGTH = 64;
		private const int MESSAGE_KEY_INDICATOR_LENGTH = 16;
		private const uint32 TETRA_VERSION = 15;
		private const int PADDING_FIELD = 15;

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

		/**
		 * The Diffie-Hellman ratchet step: the previous root key salts the extraction of
		 * the mixed shared secrets into a fresh root key and the chain key that seeds the
		 * symmetric ratchet. A post-quantum step mixes the Kyber secret in after the
		 * classical one.
		 */
		public static void derive_root_and_chain (uint8[] prior_root, uint8[] ecdh_secret,
				uint8[]? kem_secret, uint8[] conversation_dst, out uint8[] root, out uint8[] chain)
				throws Efni.Error {
			var ikm = new ByteArray ();
			ikm.append (i2osp (ecdh_secret.length, 4));
			ikm.append (ecdh_secret);
			if (kem_secret != null) {
				ikm.append (i2osp (kem_secret.length, 4));
				ikm.append (kem_secret);
			}

			var info = new ByteArray ();
			info.append (ROOT_KEY_INFO.data);
			info.append (conversation_dst);

			uint8[] derived = hkdf_extract_and_expand (ShortName.sha384, ikm.data, prior_root,
				info.data, ROOT_AND_CHAIN_LENGTH);
			root = derived[0 : MESSAGE_KEY_LENGTH];
			chain = derived[MESSAGE_KEY_LENGTH : ROOT_AND_CHAIN_LENGTH];
		}

		/**
		 * Sign with a P-256 key the way the pair-tetra and NGM transcripts are signed:
		 * SHA-256 ECDSA whose DER output is unpacked to the fixed 64-byte r‖s the wire
		 * format carries.
		 */
		/**
		 * Seal one pair-tetra message under a ratchet message key: encrypt the padded
		 * inner message with the key's derived cipher keying, and bind the ciphertext to
		 * the sender with a signature over its transcript. The message index and key
		 * indicator let the receiver place and open it within the ratchet.
		 */
		public static uint8[] seal_message (uint8[] message_key, Bytes signing_key,
				uint8[] ecdh_public_key, uint64 message_index, uint8[] plaintext,
				uint8[] authenticated_data, Bytes? kem_encapsulation = null) throws Efni.Error {
			uint8[] iv, cipher_key;
			derive_sender_authentication (message_key, out iv, out cipher_key);

			uint8[] inner = new TetraInnerMessage (new Bytes (plaintext)).serialize ();
			uint8[] ciphertext = aes_256_ctr (cipher_key, iv, pad (inner));

			uint8[] transcript = build_signature_transcript (true, TETRA_VERSION, ciphertext,
				authenticated_data);
			var message = new TetraMessage (TETRA_VERSION, new Bytes (ciphertext),
				new Bytes (sign (signing_key, transcript)), new Bytes (ecdh_public_key), message_index,
				new Bytes (derive_message_key_indicator (message_key)), kem_encapsulation);
			return message.serialize ();
		}

		/**
		 * Generate a key-agreement key whose public point is compact-representable, so
		 * the 32-byte x the wire carries recovers the one point. We keep generating until
		 * the y is the smaller of the two the x admits.
		 */
		public static Bytes generate_key_agreement_key () throws Efni.Error {
			while (true) {
				var key = new Key.generate_ec ("P-256");
				var sink = new OpenSSL.BasicIO (OpenSSL.BasicIOMethod.memory ());
				OpenSSL.Envelope.write_private_key_pem (sink, key);
				unowned uint8[] pem;
				long size = sink.get_mem_data (out pem);
				pem.length = (int) size;
				var candidate = new Bytes (pem);

				uint8[] point = public_key_point (candidate);
				if (compare_big_endian (decompress_point (compact_point (point)), point) == 0)
					return candidate;
			}
		}

		public static uint8[] compact_point (uint8[] point) {
			return point[1 : 33];
		}

		/**
		 * Recover the full P-256 point from its compact x: solve the curve equation for y
		 * (the field prime is 3 mod 4, so the square root is a modular exponentiation) and
		 * take the smaller of y and its complement, as the compact form implies.
		 */
		public static uint8[] decompress_point (uint8[] x) throws Efni.Error {
			var ctx = new OpenSSL.BigNumberContext.secure ();
			var p = new OpenSSL.BigNumber.from_big_endian (P256_PRIME);
			var three = new OpenSSL.BigNumber.from_big_endian ({ 0x03 });
			var x_value = new OpenSSL.BigNumber.from_big_endian (x);

			var y_squared = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mod_exp (y_squared, x_value, three, p, ctx);
			var three_x = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mul (three_x, three, x_value, ctx);
			OpenSSL.BigNumber.sub (y_squared, y_squared, three_x);
			OpenSSL.BigNumber.add (y_squared, y_squared, new OpenSSL.BigNumber.from_big_endian (P256_B));
			OpenSSL.BigNumber.mod_nonneg (y_squared, y_squared, p, ctx);

			var y = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mod_exp (y, y_squared,
				new OpenSSL.BigNumber.from_big_endian (P256_SQRT_EXPONENT), p, ctx);
			var complement = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.sub (complement, p, y);

			var y_bytes = new uint8[32];
			y.to_big_endian_padded (y_bytes);
			var complement_bytes = new uint8[32];
			complement.to_big_endian_padded (complement_bytes);
			if (compare_big_endian (y_bytes, complement_bytes) > 0)
				y_bytes = complement_bytes;

			var point = new uint8[65];
			point[0] = 0x04;
			Memory.copy ((uint8*) point + 1, x, 32);
			Memory.copy ((uint8*) point + 33, y_bytes, 32);
			return point;
		}

		private static int compare_big_endian (uint8[] a, uint8[] b) {
			for (int i = 0; i != a.length; i++) {
				if (a[i] != b[i])
					return (a[i] < b[i]) ? -1 : 1;
			}
			return 0;
		}

		public static uint8[] open_message (uint8[] message_key, uint8[] sender_signing_point,
				uint8[] serialized, uint8[] authenticated_data) throws Efni.Error {
			var message = TetraMessage.parse (serialized);

			uint8[] transcript = build_signature_transcript (true, message.version,
				message.ciphertext.get_data (), authenticated_data);
			if (!verify_with_point (sender_signing_point, transcript, message.signature.get_data ()))
				throw new Efni.Error.PROTOCOL ("Invalid pair-tetra message signature");

			uint8[] iv, cipher_key;
			derive_sender_authentication (message_key, out iv, out cipher_key);
			uint8[] padded = aes_256_ctr (cipher_key, iv, message.ciphertext.get_data ());
			return TetraInnerMessage.parse (padded).plaintext.get_data ();
		}

		private static uint8[] pad (uint8[] message) {
			uint target = padme (message.length);
			if (target < message.length + 2)
				target = padme (message.length + 2);

			int total = (int) target - message.length;
			int payload = total - 2;
			if (payload >= 0x80)
				payload = total - 3;

			var random = new uint8[payload];
			OpenSSL.Rng.generate (random);

			var padded = new ByteArray ();
			padded.append (message);
			padded.append (new ProtobufWriter ().append_bytes (PADDING_FIELD, random).data);
			return padded.data;
		}

		/**
		 * Assemble the transcript a pair-tetra message signature covers: the domain that
		 * separates a ratchet message from a reset one, the protocol version and the
		 * ciphertext each length-framed big endian, and the authenticated data the
		 * messaging layer binds the message to (its handles, tokens and ratchet keys).
		 */
		/**
		 * Build the authenticated data the messaging layer binds a message to: the service
		 * topic, the message's key indicator and ephemeral key, and for each party a
		 * routing binding of its handle, push token and device signing key. The signature
		 * covers it, so a peer cannot be redirected or impersonated.
		 */
		public static uint8[] build_authenticated_data (uint8[] topic, uint8[] message_key_indicator,
				uint8[] ecdh_public_key, TetraBinding[] bindings) {
			var data = new ByteArray ();
			data.append (i2osp (topic.length, 4));
			data.append (topic);
			data.append (message_key_indicator);
			data.append (ecdh_public_key);
			data.append ({ 0x01, 0x00, 0x00, 0x00 });

			foreach (var binding in bindings) {
				data.append (i2osp (binding.handle.length, 4));
				data.append (binding.handle.get_data ());
				data.append (i2osp (binding.push_token.length, 4));
				data.append (binding.push_token.get_data ());
				data.append (binding.device_key.get_data ());
			}

			data.append (new uint8[10]);
			return data.data;
		}

		public static uint8[] build_signature_transcript (bool ratchet, uint32 version,
				uint8[] ciphertext, uint8[] authenticated_data) {
			var transcript = new ByteArray ();
			transcript.append ((ratchet ? MESSAGE_SIGNATURE_DOMAIN : NO_RATCHET_SIGNATURE_DOMAIN).data);
			transcript.append (i2osp (version, 4));
			transcript.append (i2osp (ciphertext.length, 4));
			transcript.append (ciphertext);
			transcript.append (authenticated_data);
			return transcript.data;
		}

		public static uint8[] sign (Bytes private_key_pem, uint8[] data) throws Efni.Error {
			var ctx = new MessageDigestContext ();
			ctx.digest_sign_init (null, MessageDigest.fetch (null, "SHA256"), null,
				load_private_key (private_key_pem));

			size_t length = 0;
			ctx.digest_sign (null, ref length, data);
			var der = new uint8[length];
			ctx.digest_sign (der, ref length, data);
			der.length = (int) length;
			return der_to_raw (der);
		}

		public static bool verify (Bytes private_key_pem, uint8[] data, uint8[] raw_signature)
				throws Efni.Error {
			var ctx = new MessageDigestContext ();
			ctx.digest_verify_init (null, MessageDigest.fetch (null, "SHA256"), null,
				load_private_key (private_key_pem));
			return ctx.digest_verify (raw_to_der (raw_signature), data) == 1;
		}

		public static bool verify_with_point (uint8[] signing_point, uint8[] data, uint8[] raw_signature)
				throws Efni.Error {
			uint8[] point = (signing_point.length == 32) ? decompress_point (signing_point) : signing_point;
			var ctx = new MessageDigestContext ();
			ctx.digest_verify_init (null, MessageDigest.fetch (null, "SHA256"), null,
				load_public_point (point));
			return ctx.digest_verify (raw_to_der (raw_signature), data) == 1;
		}

		private static Key load_private_key (Bytes pem) {
			var source = new OpenSSL.BasicIO.from_static_memory_buffer (pem.get_data ());
			return new Key.from_private_key_pem (source);
		}

		/**
		 * The Padmé bucket a padded message rounds up to: it hides the exact plaintext
		 * length by snapping to a size whose low bits are zero, leaking only a bounded
		 * fraction of the true length.
		 */
		public static uint padme (uint length) {
			if (length < 2)
				return length;

			int e = 0;
			for (uint t = length; t > 1; t >>= 1)
				e++;

			int s = 0;
			for (uint t = e; t > 0; t >>= 1)
				s++;

			int last_bits = e - s;
			uint mask = (last_bits > 0) ? ((1u << last_bits) - 1) : 0;
			return (length + mask) & ~mask;
		}

		private const uint8[] P256_PRIME = {
			0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		};

		private const uint8[] P256_B = {
			0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7,
			0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
			0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6,
			0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
		};

		private const uint8[] P256_SQRT_EXPONENT = {
			0x3f, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00,
			0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		};

		private const uint8[] EC_P256_SPKI_PREFIX = {
			0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
			0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
		};

		public static uint8[] public_key_point (Bytes private_key_pem) throws Efni.Error {
			var sink = new OpenSSL.BasicIO (OpenSSL.BasicIOMethod.memory ());
			load_private_key (private_key_pem).to_der (sink);
			unowned uint8[] der;
			long size = sink.get_mem_data (out der);
			return der[size - 65 : size];
		}

		/**
		 * The classical half of the pair-tetra key exchange: the raw P-256 ECDH shared
		 * secret between our key and the peer's, as the ratchet mixes it in.
		 */
		public static uint8[] ecdh (Bytes our_private_key_pem, uint8[] peer_public_point)
				throws Efni.Error {
			var ctx = new KeyContext.for_key (load_private_key (our_private_key_pem));
			ctx.derive_init ();
			ctx.derive_set_peer (load_public_point (peer_public_point));

			size_t length = 0;
			ctx.derive (null, ref length);
			var secret = new uint8[length];
			ctx.derive (secret, ref length);
			secret.length = (int) length;
			return secret;
		}

		public static uint8[] kyber_encapsulate (uint8[] peer_public_key, out uint8[] encapsulation) {
			encapsulation = new uint8[Kyber.CIPHERTEXT_BYTES];
			var secret = new uint8[Kyber.SHARED_SECRET_BYTES];
			Kyber.enc (encapsulation, secret, peer_public_key);
			return secret;
		}

		public static uint8[] kyber_decapsulate (uint8[] our_secret_key, uint8[] encapsulation) {
			var secret = new uint8[Kyber.SHARED_SECRET_BYTES];
			Kyber.dec (secret, encapsulation, our_secret_key);
			return secret;
		}

		private static Key load_public_point (uint8[] point) {
			var spki = new ByteArray ();
			spki.append (EC_P256_SPKI_PREFIX);
			spki.append (point);

			var source = new OpenSSL.BasicIO.from_static_memory_buffer (spki.data);
			return new Key.from_der (source);
		}

		public static uint8[] i2osp (uint64 value, int length) {
			var octets = new uint8[length];
			for (int i = length - 1; i >= 0; i--) {
				octets[i] = (uint8) value;
				value >>= 8;
			}
			return octets;
		}

		public static uint8[] derive_message_key_indicator (uint8[] message_key) throws Efni.Error {
			return hkdf_expand (ShortName.sha384, message_key, MESSAGE_KEY_INDICATOR_INFO.data,
				MESSAGE_KEY_INDICATOR_LENGTH);
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

		private static uint8[] der_to_raw (uint8[] der) {
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

		private static uint8[] raw_to_der (uint8[] raw) {
			var body = new ByteArray ();
			body.append (der_integer (raw[0 : 32]));
			body.append (der_integer (raw[32 : 64]));

			var der = new ByteArray ();
			der.append ({ 0x30, (uint8) body.len });
			der.append (body.data);
			return der.data;
		}

		private static uint8[] der_integer (uint8[] value) {
			int start = 0;
			while (start < value.length - 1 && value[start] == 0)
				start++;
			bool pad = (value[start] & 0x80) != 0;

			var integer = new ByteArray ();
			integer.append ({ 0x02, (uint8) (value.length - start + (pad ? 1 : 0)) });
			if (pad)
				integer.append ({ 0x00 });
			integer.append (value[start : value.length]);
			return integer.data;
		}

		private static uint8[] to_bytes (int* value) {
			var bytes = new uint8[sizeof (int)];
			Memory.copy (bytes, value, sizeof (int));
			return bytes;
		}
	}
}
