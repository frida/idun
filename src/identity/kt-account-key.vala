using Efni;
using OpenSSL;
using OpenSSL.Envelope;

namespace Idun {
	/**
	 * The account's Key Transparency signing key, recovered from the synced keychain as a P-256
	 * private key in Apple's X9.63 external form. It signs a device's registration data to produce
	 * the device-key-signature that marks the device as trusted by the account: a DER structure
	 * pairing the key's id with the ECDSA signature over the registration data.
	 */
	public sealed class KtAccountKey : Object {
		public Bytes private_x963 {
			get;
			construct;
		}

		private const int COORDINATE_LENGTH = 32;
		private const int POINT_LENGTH = 1 + 2 * COORDINATE_LENGTH;
		private const int PRIVATE_LENGTH = POINT_LENGTH + COORDINATE_LENGTH;

		public KtAccountKey (Bytes private_x963) throws Efni.Error {
			if (private_x963.length != PRIVATE_LENGTH)
				throw new Efni.Error.PROTOCOL ("KT account key is not a P-256 X9.63 private blob");
			Object (private_x963: private_x963);
		}

		/**
		 * The 20-byte account-KT-key id the device-key-signature carries: SHA-1 of the public
		 * point, which is how the keychain labels the key and how registrations name it.
		 */
		public Bytes account_key_id () {
			var checksum = new Checksum (ChecksumType.SHA1);
			checksum.update (private_x963.get_data ()[0 : POINT_LENGTH], POINT_LENGTH);
			var digest = new uint8[20];
			size_t length = digest.length;
			checksum.get_digest (digest, ref length);
			return new Bytes (digest);
		}

		/**
		 * Sign the device's registration data, producing the device-key-signature: a DER sequence
		 * of the account-KT-key id, a version integer, and the ECDSA signature over the data.
		 */
		public Bytes sign_registration_data (uint8[] registration_data) throws Efni.Error {
			uint8[] signature = OctagonCrypto.sign (to_pem (), registration_data, "SHA256");

			var body = new ByteArray ();
			append_tlv (body, 0x04, account_key_id ().get_data ());
			append_tlv (body, 0x02, { 0x01 });
			append_tlv (body, 0x04, signature);

			var result = new ByteArray ();
			append_tlv (result, 0x30, body.data);
			return new Bytes (result.data);
		}

		/**
		 * The registration data the signature covers: the device's NGM public identity, the NGM
		 * message-protection version, and the Key Transparency version.
		 */
		public static uint8[] build_registration_data (uint8[] ngm_device_identity, int ngm_version,
				int kt_version) {
			return new ProtobufWriter ()
				.append_bytes (1, ngm_device_identity)
				.append_varint (2, ngm_version)
				.append_varint (3, kt_version)
				.data;
		}

		/**
		 * The SubjectPublicKeyInfo DER of the key's public half, which verifies a
		 * device-key-signature's ECDSA component.
		 */
		public Bytes public_spki () throws Efni.Error {
			var sink = new OpenSSL.BasicIO (OpenSSL.BasicIOMethod.memory ());
			load_key ().to_der (sink);
			unowned uint8[] der;
			long size = sink.get_mem_data (out der);
			der.length = (int) size;
			return new Bytes (der);
		}

		private Bytes to_pem () throws Efni.Error {
			var sink = new OpenSSL.BasicIO (OpenSSL.BasicIOMethod.memory ());
			OpenSSL.Envelope.write_private_key_pem (sink, load_key ());
			unowned uint8[] pem;
			long size = sink.get_mem_data (out pem);
			pem.length = (int) size;
			return new Bytes (pem);
		}

		private Key load_key () throws Efni.Error {
			var ec = new EcKey.by_curve_name (NID_X9_62_prime256v1);
			unowned EcGroup group = ec.get0_group ();
			var ctx = new BigNumberContext.secure ();
			var data = private_x963.get_data ();

			var scalar = new BigNumber.from_big_endian (data[POINT_LENGTH : PRIVATE_LENGTH]);
			if (ec.set_private_key (scalar) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to set KT account private scalar");

			var point = new EcPoint (group);
			if (point.oct2point (group, data[0 : POINT_LENGTH], ctx) != 1 ||
					ec.set_public_key (point) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to set KT account public point");

			var key = new Key ();
			if (key.set1_ec_key (ec) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to wrap KT account key");
			return key;
		}

		private static void append_tlv (ByteArray der, uint8 tag, uint8[] value) {
			der.append ({ tag });
			if (value.length < 0x80) {
				der.append ({ (uint8) value.length });
			} else {
				der.append ({ 0x81, (uint8) value.length });
			}
			der.append (value);
		}
	}
}
