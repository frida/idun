using Efni;
using OpenSSL;
using OpenSSL.Envelope;

namespace Idun {
	/**
	 * Protected Cloud Storage key unwrapping. A PCS-protected keychain item seals its secret to a
	 * PCS service key with corecrypto's RFC 6637 scheme (ECDH over P-256 with a compact ephemeral
	 * key, a SHA-256 key-encryption key, and AES key wrap). The PCS service private keys are
	 * themselves ordinary keychain items; given the one whose public key an item sealed to, this
	 * recovers the item's wrapped key — for the account Key Transparency signing key, the private
	 * key that mints the device-key-signature.
	 */
	public sealed class PcsKey : Object {
		private const int COORDINATE_LENGTH = 32;
		private static uint8[] P256_OID = { 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

		/**
		 * The P-256 private scalar of a PCS service key stored in a keychain item's v_Data: either
		 * a V1 SEQUENCE whose first octet string is the compact key, or a V2 [APPLICATION 5] whose
		 * octet string holds a protobuf whose field 1's field 1 is the compact encryption key.
		 */
		public static uint8[] parse_private_scalar (uint8[] der) throws Efni.Error {
			uint8 tag = der[0];
			int offset, length;
			read_tlv_header (der, 0, out offset, out length);
			uint8[] compact;
			if (tag == 0x65) {
				int inner_offset, inner_length;
				read_tlv_header (der, offset, out inner_offset, out inner_length);
				uint8[] protobuf = der[inner_offset : inner_offset + inner_length];
				uint8[] encryption = protobuf_field (protobuf, 1);
				compact = protobuf_field (encryption, 1);
			} else {
				int octet_offset, octet_length;
				read_tlv_header (der, offset, out octet_offset, out octet_length);
				compact = der[octet_offset : octet_offset + octet_length];
			}
			return (compact.length == 64) ? compact[32 : 64] : compact;
		}

		/**
		 * The compact public key (the 32-byte X coordinate) of a P-256 private scalar, used to
		 * match a PCS service key against the public key an item sealed to.
		 */
		public static uint8[] public_x (uint8[] scalar) throws Efni.Error {
			return public_point (scalar)[1 : 1 + COORDINATE_LENGTH];
		}

		/**
		 * The uncompressed public point (04 || X || Y) of a P-256 private scalar.
		 */
		public static uint8[] public_point (uint8[] scalar) throws Efni.Error {
			unowned EcGroup group;
			var ec = load_private (scalar, out group);
			var ctx = new BigNumberContext.secure ();
			var encoded = new uint8[1 + 2 * COORDINATE_LENGTH];
			ec.get0_public_key ().point2oct (group, PointConversionForm.UNCOMPRESSED, encoded,
				encoded.length, ctx);
			return encoded;
		}

		/**
		 * Unwrap a key sealed to this scalar's public key: ECDH to the compact ephemeral key, the
		 * RFC 6637 key-encryption key, AES key unwrap, then the OpenPGP padding and checksum the
		 * scheme appends.
		 */
		public static uint8[] rfc6637_unwrap (uint8[] recipient_scalar, uint8[] ephemeral_x,
				uint8[] wrapped_blob) throws Efni.Error {
			uint8[] secret = ecdh (recipient_scalar, ephemeral_x);

			var checksum = new Checksum (ChecksumType.SHA256);
			uint8[] counter = { 0x00, 0x00, 0x00, 0x01 };
			checksum.update (counter, counter.length);
			checksum.update (secret, secret.length);
			checksum.update (P256_OID, P256_OID.length);
			uint8[] params = { 18, 0x03, 0x01, 8, 7 };
			checksum.update (params, params.length);
			uint8[] sender = "Anonymous Sender    ".data;
			checksum.update (sender, sender.length);
			var fingerprint = new uint8[20];
			uint8[] label = "fingerprint".data;
			Memory.copy (fingerprint, label, label.length);
			checksum.update (fingerprint, fingerprint.length);
			var digest = new uint8[32];
			size_t digest_length = digest.length;
			checksum.get_digest (digest, ref digest_length);

			uint8[] message = OctagonCrypto.aes_kw_unwrap (digest[0 : 16], wrapped_blob);

			int pad = message[message.length - 1];
			if (pad == 0 || pad > message.length - 3)
				throw new Efni.Error.PROTOCOL ("Bad RFC 6637 padding");
			uint8[] key = message[1 : message.length - pad - 2];

			uint32 checksum_value = 0;
			foreach (uint8 b in key)
				checksum_value += b;
			uint32 stored = ((uint32) message[1 + key.length] << 8) | message[2 + key.length];
			if ((checksum_value & 0xffff) != stored)
				throw new Efni.Error.PROTOCOL ("Bad RFC 6637 checksum");
			return key;
		}

		private static uint8[] ecdh (uint8[] recipient_scalar, uint8[] ephemeral_x)
				throws Efni.Error {
			unowned EcGroup group;
			var ours = load_private (recipient_scalar, out group);
			var ctx = new BigNumberContext.secure ();

			var point = new EcPoint (group);
			var compressed = new uint8[1 + COORDINATE_LENGTH];
			compressed[0] = 0x03;
			Memory.copy ((uint8 *) compressed + 1, ephemeral_x, COORDINATE_LENGTH);
			if (point.oct2point (group, compressed, ctx) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to recover PCS ephemeral point");
			var peer = new EcKey.by_curve_name (NID_X9_62_prime256v1);
			peer.set_public_key (point);

			var ours_key = new Key ();
			ours_key.set1_ec_key (ours);
			var peer_key = new Key ();
			peer_key.set1_ec_key (peer);

			var derive = new KeyContext.for_key (ours_key);
			if (derive.derive_init () != 1 || derive.derive_set_peer (peer_key) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to initialize PCS ECDH");
			size_t length = 0;
			derive.derive (null, ref length);
			var secret = new uint8[length];
			if (derive.derive (secret, ref length) != 1)
				throw new Efni.Error.PROTOCOL ("PCS ECDH derivation failed");
			secret.length = (int) length;
			return secret;
		}

		private static EcKey load_private (uint8[] scalar, out unowned EcGroup group)
				throws Efni.Error {
			var ec = new EcKey.by_curve_name (NID_X9_62_prime256v1);
			group = ec.get0_group ();
			var ctx = new BigNumberContext.secure ();
			var d = new BigNumber.from_big_endian (scalar);
			if (ec.set_private_key (d) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to set PCS private scalar");
			var point = new EcPoint (group);
			if (point.mul (group, d, null, null, ctx) != 1 || ec.set_public_key (point) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to derive PCS public point");
			return ec;
		}

		private static void read_tlv_header (uint8[] der, int position, out int content_offset,
				out int content_length) {
			int i = position + 1;
			int length = der[i];
			i += 1;
			if ((length & 0x80) != 0) {
				int count = length & 0x7f;
				length = 0;
				for (int j = 0; j != count; j++)
					length = (length << 8) | der[i++];
			}
			content_offset = i;
			content_length = length;
		}

		private static uint8[] protobuf_field (uint8[] data, int field) throws Efni.Error {
			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				if (reader.read_field (out wire_type) == field && wire_type == 2)
					return reader.read_bytes ();
				reader.skip (wire_type);
			}
			throw new Efni.Error.PROTOCOL ("PCS key protobuf missing field %d", field);
		}
	}

	/**
	 * A PCS master key: the symmetric key an item's service is protected under, from which
	 * label-derived working keys are computed. A PCS ciphertext (version 3) names its key by a
	 * prefix of the key's id and is AES-GCM-sealed under the derived encryption key, authenticating
	 * its own header together with the caller's associated data.
	 */
	public sealed class PcsMasterKey : Object {
		public Bytes raw {
			get;
			construct;
		}

		public PcsMasterKey (Bytes raw) {
			Object (raw: raw);
		}

		public Bytes key_id () {
			return mac (derive ("master key id labell".data), "M key input data 2 u".data);
		}

		public PcsMasterKey share_variant () {
			return new PcsMasterKey (new Bytes (derive ("MsaeEooevaX fooo 012".data)));
		}

		public Bytes mac_over (uint8[] data) {
			return mac (derive ("hmackey-of-masterkey".data), data);
		}

		/**
		 * Decrypt a version-3 PCS ciphertext: 0x03 ‖ id[0:2] ‖ n ‖ id[2:2+n] ‖ iv(12) ‖ tag(12) ‖
		 * data, AES-GCM under the derived encryption key, with the header and caller data
		 * authenticated.
		 */
		public uint8[] decrypt (uint8[] ciphertext, uint8[] associated_data) throws Efni.Error {
			int header_length;
			uint8[] wanted = ciphertext_key_id (ciphertext, out header_length);
			if (!id_has_prefix (wanted))
				throw new Efni.Error.PROTOCOL ("PCS ciphertext is for a different key");

			uint8[] iv = ciphertext[header_length : header_length + 12];
			uint8[] tag = ciphertext[header_length + 12 : header_length + 24];
			uint8[] data = ciphertext[header_length + 24 : ciphertext.length];

			var aad = new uint8[header_length + associated_data.length];
			Memory.copy (aad, ciphertext, header_length);
			Memory.copy ((uint8 *) aad + header_length, associated_data, associated_data.length);

			return OctagonCrypto.aes_gcm_decrypt (derive ("encryption key key m".data), iv, data,
				tag, aad);
		}

		public static uint8[] ciphertext_key_id (uint8[] ciphertext, out int header_length)
				throws Efni.Error {
			if (ciphertext.length < 4 || ciphertext[0] != 3)
				throw new Efni.Error.PROTOCOL ("Unsupported PCS ciphertext version");

			int n = ciphertext[3];
			header_length = 4 + n;

			var id = new uint8[2 + n];
			id[0] = ciphertext[1];
			id[1] = ciphertext[2];
			Memory.copy ((uint8 *) id + 2, (uint8 *) ciphertext + 4, n);
			return id;
		}

		private bool id_has_prefix (uint8[] prefix) {
			uint8[] id = key_id ().get_data ();
			if (prefix.length > id.length)
				return false;
			return Memory.cmp (id, prefix, prefix.length) == 0;
		}

		private uint8[] derive (uint8[] label) {
			return kdf_ctr_hmac (raw.get_data (), label, raw.length);
		}

		private static uint8[] kdf_ctr_hmac (uint8[] key, uint8[] label, int length) {
			var suffix = new ByteArray ();
			suffix.append (label);
			suffix.append ({ 0x00 });
			suffix.append (be32 ((uint32) length * 8));

			var output = new ByteArray ();
			uint32 counter = 1;
			while (output.len < length) {
				var block = new ByteArray ();
				block.append (be32 (counter));
				block.append (suffix.data);
				output.append (mac (key, block.data).get_data ());
				counter++;
			}

			return output.data[0 : length];
		}

		private static Bytes mac (uint8[] key, uint8[] data) {
			var hmac = new Hmac (ChecksumType.SHA256, key);
			hmac.update (data);
			var digest = new uint8[32];
			size_t length = digest.length;
			hmac.get_digest (digest, ref length);
			return new Bytes (digest);
		}

		private static uint8[] be32 (uint32 value) {
			return {
				(uint8) (value >> 24), (uint8) (value >> 16), (uint8) (value >> 8), (uint8) value
			};
		}
	}
}
