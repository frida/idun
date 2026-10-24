using Efni;

namespace Idun {
	/**
	 * A peer's published NGM prekey, as a lookup returns it: the compact key-agreement
	 * key and the Kyber key a sender needs to establish a pair-tetra session, and the
	 * compact signing key it verifies the peer's messages against.
	 */
	public sealed class NgmPeerPrekey : Object {
		public Bytes ecdh_point {
			get;
			construct;
		}

		public Bytes kyber_public {
			get;
			construct;
		}

		public Bytes signing_point {
			get;
			construct;
		}

		public NgmPeerPrekey (Bytes ecdh_point, Bytes kyber_public, Bytes signing_point) {
			Object (ecdh_point: ecdh_point, kyber_public: kyber_public, signing_point: signing_point);
		}

		public static NgmPeerPrekey parse (Bytes prekey_data, Bytes kt_loggable_data) throws Efni.Error {
			Bytes? ecdh_point = null;
			Bytes? kyber_public = null;

			var reader = new ProtobufReader (prekey_data.get_data ());
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						ecdh_point = new Bytes (reader.read_bytes ());
						break;
					case 4:
						kyber_public = parse_kyber (reader.read_bytes ());
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}

			Bytes? signing_point = parse_signing_point (kt_loggable_data.get_data ());

			if (ecdh_point == null || kyber_public == null || signing_point == null)
				throw new Efni.Error.PROTOCOL ("Incomplete NGM peer prekey");

			return new NgmPeerPrekey (ecdh_point, kyber_public, signing_point);
		}

		private static Bytes? parse_kyber (uint8[] tetra_submessage) throws Efni.Error {
			var reader = new ProtobufReader (tetra_submessage);
			while (reader.has_more) {
				uint8 wire_type;
				if (reader.read_field (out wire_type) == 1)
					return new Bytes (reader.read_bytes ());
				reader.skip (wire_type);
			}
			return null;
		}

		private static Bytes? parse_signing_point (uint8[] kt_loggable_data) throws Efni.Error {
			var reader = new ProtobufReader (kt_loggable_data);
			while (reader.has_more) {
				uint8 wire_type;
				if (reader.read_field (out wire_type) == 1)
					return parse_public_key (reader.read_bytes ());
				reader.skip (wire_type);
			}
			return null;
		}

		private static Bytes? parse_public_key (uint8[] ngm_public_identity) throws Efni.Error {
			var reader = new ProtobufReader (ngm_public_identity);
			while (reader.has_more) {
				uint8 wire_type;
				if (reader.read_field (out wire_type) == 1)
					return new Bytes (reader.read_bytes ());
				reader.skip (wire_type);
			}
			return null;
		}
	}
}
