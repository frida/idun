using Efni;
using OpenSSL;
using OpenSSL.Envelope;

namespace Idun {
	/**
	 * The key operations an Octagon peer identity is built on: P-384 keys stored in Apple's X9.63
	 * external representation, ECDSA signatures with the "typed" domain-separation prefix Octagon
	 * puts in front of every signed structure, the peer-id hash, and the ECIES unwrap that opens a
	 * CKKS TLKShare with a peer's encryption key. All of it is keyed by the X9.63 private blobs the
	 * escrow bottle hands back, so recovery never has to re-generate the recovered peer's keys.
	 */
	public sealed class OctagonPeerKeys : Object {
		public const string PERMANENT_INFO_SIG_TYPE = "TPPB.PeerPermanentInfo";
		public const string STABLE_INFO_SIG_TYPE = "TPPB.PeerStableInfo";
		public const string DYNAMIC_INFO_SIG_TYPE = "TPPB.PeerDynamicInfo";
		public const string VOUCHER_SIG_TYPE = "TPPB.Voucher";

		private const int COORDINATE_LENGTH = 48;
		private const int POINT_LENGTH = 1 + 2 * COORDINATE_LENGTH;         // 0x04 || X || Y
		private const int PRIVATE_LENGTH = POINT_LENGTH + COORDINATE_LENGTH; // || D

		/**
		 * ECDSA P-384 / SHA-384 over the domain-separated data, with the signature-type name
		 * prefixed exactly as Octagon's `prefixedData()` does.
		 */
		public static uint8[] sign_prefixed (uint8[] private_x963, uint8[] data, string sig_type)
				throws Efni.Error {
			return OctagonCrypto.sign (to_pem (load_private (private_x963)),
				prefixed_data (data, sig_type), "SHA384");
		}

		/**
		 * Verify a typed signature against the signer's SubjectPublicKeyInfo.
		 */
		public static bool verify_prefixed (uint8[] spki, uint8[] data, uint8[] signature,
				string sig_type) throws Efni.Error {
			return OctagonCrypto.verify (spki, prefixed_data (data, sig_type), signature, "SHA384");
		}

		/**
		 * The SubjectPublicKeyInfo DER of the public half of an X9.63 private key.
		 */
		public static Bytes public_spki (uint8[] private_x963) throws Efni.Error {
			var sink = new OpenSSL.BasicIO (OpenSSL.BasicIOMethod.memory ());
			load_private (private_x963).to_der (sink);
			unowned uint8[] data;
			long size = sink.get_mem_data (out data);
			data.length = (int) size;
			return new Bytes (data);
		}

		/**
		 * TPHashBuilder: "<ALGO>:" + base64(digest).
		 */
		public static string tphash (uint8[] data, string algo = "SHA256") {
			var type = (algo == "SHA384") ? ChecksumType.SHA384 : ChecksumType.SHA256;
			var checksum = new Checksum (type);
			checksum.update (data, data.length);
			int length = (type == ChecksumType.SHA384) ? 48 : 32;
			var digest = new uint8[length];
			size_t digest_length = digest.length;
			checksum.get_digest (digest, ref digest_length);
			return algo + ":" + Base64.encode (digest);
		}

		/**
		 * peerID = tphash(permanentInfo data || sig): the id commits to both the signed fields and
		 * the randomized signature, so it is fixed once and only re-checked by verifiers.
		 */
		public static string derive_peer_id (uint8[] permanent_data, uint8[] signature) {
			var combined = new uint8[permanent_data.length + signature.length];
			Memory.copy (combined, permanent_data, permanent_data.length);
			Memory.copy ((uint8 *) combined + permanent_data.length, signature, signature.length);
			return tphash (combined);
		}

		public static uint8[] prefixed_data (uint8[] data, string sig_type) {
			var prefix = sig_type.data;
			var result = new uint8[prefix.length + data.length];
			Memory.copy (result, prefix, prefix.length);
			Memory.copy ((uint8 *) result + prefix.length, data, data.length);
			return result;
		}

		/**
		 * ECIES decrypt as SecurityFoundation performs it for a TLKShare: ECDH to the ephemeral
		 * sender key, an X9.63 KDF over the shared secret (info = the ephemeral public key) into a
		 * 32-byte AES key and 16-byte IV, then AES-256-GCM over the ciphertext and 16-byte tag.
		 */
		public static uint8[] ecies_decrypt (uint8[] recipient_private_x963,
				uint8[] ephemeral_public_x963, uint8[] ciphertext, uint8[] auth_code)
				throws Efni.Error {
			uint8[] secret = ecdh (load_private (recipient_private_x963),
				load_public_point (ephemeral_public_x963));
			uint8[] derived = x963_kdf (secret, ephemeral_public_x963, 48);
			return OctagonCrypto.aes_256_gcm_decrypt (derived[0 : 32], derived[32 : 48],
				ciphertext, auth_code);
		}

		/**
		 * The inverse of {@link ecies_decrypt}, used by tests that stand in for the sender sealing a
		 * TLKShare to a peer's encryption key.
		 */
		public static void ecies_encrypt (uint8[] recipient_public_x963, uint8[] plaintext,
				out uint8[] ephemeral_public_x963, out uint8[] ciphertext, out uint8[] auth_code)
				throws Efni.Error {
			uint8[] ephemeral_private = generate_private_x963 ();
			ephemeral_public_x963 = ephemeral_private[0 : POINT_LENGTH];
			uint8[] secret = ecdh (load_private (ephemeral_private),
				load_public_point (recipient_public_x963));
			uint8[] derived = x963_kdf (secret, ephemeral_public_x963, 48);
			uint8[] tag;
			ciphertext = OctagonCrypto.aes_256_gcm_encrypt (derived[0 : 32], derived[32 : 48],
				plaintext, out tag);
			auth_code = tag;
		}

		/**
		 * Unwrap a CKKS TLKShare: ECIES-decrypt the wrapped key with the recipient peer's
		 * encryption key, then read the CuttlefishSerializedKey it yields — the TLK uuid (field 1)
		 * and the top-level key bytes (field 4), not raw key material.
		 */
		public static void unwrap_tlk (uint8[] recipient_private_x963,
				uint8[] ephemeral_public_x963, uint8[] ciphertext, uint8[] auth_code,
				out string uuid, out Bytes key) throws Efni.Error {
			uint8[] serialized = ecies_decrypt (recipient_private_x963, ephemeral_public_x963,
				ciphertext, auth_code);
			uuid = "";
			key = new Bytes ({});
			var reader = new ProtobufReader (serialized);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						uuid = reader.read_string ();
						break;
					case 4:
						key = new Bytes (reader.read_bytes ());
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}
		}

		private static uint8[] ecdh (Key ours, Key peer) throws Efni.Error {
			var ctx = new KeyContext.for_key (ours);
			if (ctx.derive_init () != 1 || ctx.derive_set_peer (peer) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to initialize ECDH");
			size_t length = 0;
			ctx.derive (null, ref length);
			var secret = new uint8[length];
			if (ctx.derive (secret, ref length) != 1)
				throw new Efni.Error.PROTOCOL ("ECDH derivation failed");
			secret.length = (int) length;
			return secret;
		}

		// ANSI X9.63 KDF with SHA-256: H(secret || counter_be32 || shared_info), counter from 1.
		private static uint8[] x963_kdf (uint8[] secret, uint8[] shared_info, int length) {
			var output = new uint8[0];
			uint32 counter = 1;
			while (output.length < length) {
				var checksum = new Checksum (ChecksumType.SHA256);
				checksum.update (secret, secret.length);
				uint8[] counter_be = {
					(uint8) ((counter >> 24) & 0xff), (uint8) ((counter >> 16) & 0xff),
					(uint8) ((counter >> 8) & 0xff), (uint8) (counter & 0xff)
				};
				checksum.update (counter_be, counter_be.length);
				checksum.update (shared_info, shared_info.length);
				var block = new uint8[32];
				size_t block_length = block.length;
				checksum.get_digest (block, ref block_length);
				int prior = output.length;
				output.resize (prior + 32);
				Memory.copy ((uint8 *) output + prior, block, 32);
				counter++;
			}
			output.resize (length);
			return output;
		}

		private static Key load_private (uint8[] x963) throws Efni.Error {
			if (x963.length != PRIVATE_LENGTH)
				throw new Efni.Error.PROTOCOL ("Octagon peer private key is not a P-384 X9.63 blob");
			var ec = new EcKey.by_curve_name (NID_secp384r1);
			unowned EcGroup group = ec.get0_group ();
			var ctx = new BigNumberContext.secure ();

			var scalar = new BigNumber.from_big_endian (x963[POINT_LENGTH : PRIVATE_LENGTH]);
			if (ec.set_private_key (scalar) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to set peer private scalar");

			var point = new EcPoint (group);
			if (point.oct2point (group, x963[0 : POINT_LENGTH], ctx) != 1 ||
					ec.set_public_key (point) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to set peer public point");

			var key = new Key ();
			if (key.set1_ec_key (ec) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to wrap peer EC key");
			return key;
		}

		private static Key load_public_point (uint8[] point_x963) throws Efni.Error {
			var ec = new EcKey.by_curve_name (NID_secp384r1);
			unowned EcGroup group = ec.get0_group ();
			var ctx = new BigNumberContext.secure ();
			var point = new EcPoint (group);
			if (point.oct2point (group, point_x963, ctx) != 1 || ec.set_public_key (point) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to parse peer public point");
			var key = new Key ();
			if (key.set1_ec_key (ec) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to wrap peer public key");
			return key;
		}

		// A fresh P-384 key in X9.63 private form (0x04 || X || Y || D), via a random scalar reduced
		// into [1, n-1].
		public static uint8[] generate_private_x963 () throws Efni.Error {
			var ec = new EcKey.by_curve_name (NID_secp384r1);
			unowned EcGroup group = ec.get0_group ();
			unowned BigNumber order = group.get0_order ();
			var ctx = new BigNumberContext.secure ();

			var seed = new uint8[COORDINATE_LENGTH];
			OpenSSL.Rng.generate (seed);
			var one = new BigNumber.from_big_endian ({ 0x01 });
			var order_minus_one = new BigNumber ();
			BigNumber.sub (order_minus_one, order, one);
			var scalar = new BigNumber ();
			BigNumber.mod_nonneg (scalar, new BigNumber.from_big_endian (seed), order_minus_one, ctx);
			BigNumber.add (scalar, scalar, one);

			var point = new EcPoint (group);
			if (point.mul (group, scalar, null, null, ctx) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to derive peer public point");

			var encoded = new uint8[POINT_LENGTH];
			if (point.point2oct (group, PointConversionForm.UNCOMPRESSED, encoded, encoded.length, ctx)
					!= POINT_LENGTH)
				throw new Efni.Error.PROTOCOL ("Unable to encode peer public point");

			var result = new uint8[PRIVATE_LENGTH];
			Memory.copy (result, encoded, POINT_LENGTH);
			var scalar_bytes = new uint8[COORDINATE_LENGTH];
			scalar.to_big_endian_padded (scalar_bytes);
			Memory.copy ((uint8 *) result + POINT_LENGTH, scalar_bytes, COORDINATE_LENGTH);
			return result;
		}

		private static Bytes to_pem (Key key) {
			var sink = new OpenSSL.BasicIO (OpenSSL.BasicIOMethod.memory ());
			OpenSSL.Envelope.write_private_key_pem (sink, key);
			unowned uint8[] data;
			long size = sink.get_mem_data (out data);
			data.length = (int) size;
			return new Bytes (data);
		}
	}
}
