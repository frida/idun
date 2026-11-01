using Efni;
using OpenSSL;
using OpenSSL.Envelope;

namespace Idun {
	/**
	 * The keys an Octagon bottle is sealed under, derived from the escrow secret and a
	 * per-bottle salt: a P-384 signing key and encryption key, and a symmetric key that
	 * wraps the bottle's contents. A recovering device re-derives these from the same
	 * secret to authenticate and open the bottle. The private keys are kept in PEM form
	 * to match the rest of Idun's key handling.
	 */
	public sealed class OctagonEscrowKeys : Object {
		public Bytes signing_key {
			get;
			construct;
		}

		public Bytes encryption_key {
			get;
			construct;
		}

		public Bytes symmetric_key {
			get;
			construct;
		}

		public Bytes signing_spki {
			get;
			construct;
		}

		public Bytes encryption_spki {
			get;
			construct;
		}

		private const string SIGNING_INFO = "Escrow Signing Private Key";
		private const string ENCRYPTION_INFO = "Escrow Encryption Private Key";
		private const string SYMMETRIC_INFO = "Escrow Symmetric Key";
		private const int EC_SEED_LENGTH = 56;
		private const int SYMMETRIC_KEY_LENGTH = 32;

		private OctagonEscrowKeys (Bytes signing_key, Bytes encryption_key, Bytes symmetric_key,
				Bytes signing_spki, Bytes encryption_spki) {
			Object (signing_key: signing_key, encryption_key: encryption_key, symmetric_key: symmetric_key,
				signing_spki: signing_spki, encryption_spki: encryption_spki);
		}

		public static OctagonEscrowKeys derive (uint8[] secret, string bottle_salt) throws Efni.Error {
			uint8[] salt = bottle_salt.data;

			Key signing = derive_ec_key (secret, salt, SIGNING_INFO);
			Key encryption = derive_ec_key (secret, salt, ENCRYPTION_INFO);
			uint8[] symmetric = TetraCrypto.hkdf_extract_and_expand (ShortName.sha384, secret, salt,
				SYMMETRIC_INFO.data, SYMMETRIC_KEY_LENGTH);

			return new OctagonEscrowKeys (export_private_key (signing), export_private_key (encryption),
				new Bytes (symmetric), subject_public_key_info (signing),
				subject_public_key_info (encryption));
		}

		private static Key derive_ec_key (uint8[] secret, uint8[] salt, string info) throws Efni.Error {
			uint8[] seed = TetraCrypto.hkdf_extract_and_expand (ShortName.sha384, secret, salt,
				info.data, EC_SEED_LENGTH);
			return deterministic_p384_key (seed);
		}

		/**
		 * Reproduce corecrypto's FIPS deterministic EC key generation (FIPS 186-4 B.4.1,
		 * "key pair generation using extra random bits"): interpret the seed as a big
		 * integer, reduce it modulo the group order minus one, and add one, so the private
		 * scalar lands uniformly in [1, n-1]. The public point is the scalar times the
		 * generator.
		 */
		private static Key deterministic_p384_key (uint8[] seed) throws Efni.Error {
			var ec = new EcKey.by_curve_name (NID_secp384r1);
			unowned EcGroup group = ec.get0_group ();
			unowned BigNumber order = group.get0_order ();

			var ctx = new BigNumberContext.secure ();
			var one = new BigNumber.from_big_endian ({ 0x01 });
			var order_minus_one = new BigNumber ();
			BigNumber.sub (order_minus_one, order, one);

			var scalar = new BigNumber ();
			BigNumber.mod_nonneg (scalar, new BigNumber.from_big_endian (seed), order_minus_one, ctx);
			BigNumber.add (scalar, scalar, one);

			if (ec.set_private_key (scalar) != 1)
				throw new Efni.Error.NOT_SUPPORTED ("Unable to set escrow private scalar");

			var point = new EcPoint (group);
			if (point.mul (group, scalar, null, null, ctx) != 1)
				throw new Efni.Error.NOT_SUPPORTED ("Unable to derive escrow public point");
			if (ec.set_public_key (point) != 1)
				throw new Efni.Error.NOT_SUPPORTED ("Unable to set escrow public point");

			var key = new Key ();
			if (key.set1_ec_key (ec) != 1)
				throw new Efni.Error.NOT_SUPPORTED ("Unable to wrap escrow EC key");
			return key;
		}

		private static Bytes export_private_key (Key key) {
			var sink = new OpenSSL.BasicIO (OpenSSL.BasicIOMethod.memory ());
			OpenSSL.Envelope.write_private_key_pem (sink, key);
			unowned uint8[] data;
			long size = sink.get_mem_data (out data);
			data.length = (int) size;
			return new Bytes (data);
		}

		private static Bytes subject_public_key_info (Key key) {
			var sink = new OpenSSL.BasicIO (OpenSSL.BasicIOMethod.memory ());
			key.to_der (sink);
			unowned uint8[] data;
			long size = sink.get_mem_data (out data);
			data.length = (int) size;
			return new Bytes (data);
		}
	}
}
