using Efni;

namespace Idun {
	/**
	 * A recovered Octagon bottle: the envelope an iCloud-Keychain trusted device
	 * escrows so another device can rejoin the account's trust circle. It names the
	 * peer it belongs to, pins the escrow and peer public keys that authenticate it,
	 * and carries the peer's private keys encrypted under a key derived from the
	 * escrow secret. Recovering the bottle yields the Octagon peer identity Idun needs
	 * to obtain the account key-transparency key and mint its device-key-signature.
	 */
	public sealed class OctagonBottle : Object {
		public string peer_id {
			get;
			construct;
		}

		public string bottle_id {
			get;
			construct;
		}

		public Bytes escrowed_signing_spki {
			get;
			construct;
		}

		public Bytes escrowed_encryption_spki {
			get;
			construct;
		}

		public Bytes peer_signing_spki {
			get;
			construct;
		}

		public Bytes peer_encryption_spki {
			get;
			construct;
		}

		public OctagonAuthenticatedCiphertext contents {
			get;
			construct;
		}

		public OctagonBottle (string peer_id, string bottle_id, Bytes escrowed_signing_spki,
				Bytes escrowed_encryption_spki, Bytes peer_signing_spki, Bytes peer_encryption_spki,
				OctagonAuthenticatedCiphertext contents) {
			Object (peer_id: peer_id, bottle_id: bottle_id, escrowed_signing_spki: escrowed_signing_spki,
				escrowed_encryption_spki: escrowed_encryption_spki, peer_signing_spki: peer_signing_spki,
				peer_encryption_spki: peer_encryption_spki, contents: contents);
		}

		public static OctagonBottle parse (uint8[] data) throws Efni.Error {
			string peer_id = "";
			string bottle_id = "";
			Bytes? escrowed_signing_spki = null;
			Bytes? escrowed_encryption_spki = null;
			Bytes? peer_signing_spki = null;
			Bytes? peer_encryption_spki = null;
			OctagonAuthenticatedCiphertext? contents = null;

			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						peer_id = reader.read_string ();
						break;
					case 2:
						bottle_id = reader.read_string ();
						break;
					case 8:
						escrowed_signing_spki = new Bytes (reader.read_bytes ());
						break;
					case 9:
						escrowed_encryption_spki = new Bytes (reader.read_bytes ());
						break;
					case 10:
						peer_signing_spki = new Bytes (reader.read_bytes ());
						break;
					case 11:
						peer_encryption_spki = new Bytes (reader.read_bytes ());
						break;
					case 12:
						contents = OctagonAuthenticatedCiphertext.parse (reader.read_bytes ());
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}

			if (escrowed_signing_spki == null || escrowed_encryption_spki == null ||
					peer_signing_spki == null || peer_encryption_spki == null || contents == null)
				throw new Efni.Error.PROTOCOL ("Incomplete Octagon bottle");

			return new OctagonBottle (peer_id, bottle_id, escrowed_signing_spki, escrowed_encryption_spki,
				peer_signing_spki, peer_encryption_spki, contents);
		}

		/**
		 * Recover the peer identity a bottle carries. Re-derives the escrow keys from the
		 * escrow secret, checks the bottle was escrowed under them, verifies the escrow and
		 * peer signatures over the bottle, and decrypts its contents. The signatures are
		 * taken over the bottle bytes exactly as received, so those are passed in alongside
		 * the two detached signatures the escrow record stores next to the bottle.
		 */
		public static OctagonBottleContents open (uint8[] bottle, uint8[] secret, string bottle_salt,
				uint8[] signature_using_escrow, uint8[] signature_using_peer) throws Efni.Error {
			var escrow = OctagonEscrowKeys.derive (secret, bottle_salt);
			var parsed = parse (bottle);

			if (parsed.escrowed_signing_spki.compare (escrow.signing_spki) != 0)
				throw new Efni.Error.PROTOCOL ("Escrow secret does not match the bottle");

			if (!OctagonCrypto.verify (escrow.signing_spki.get_data (), bottle, signature_using_escrow))
				throw new Efni.Error.PROTOCOL ("Invalid escrow signature on the bottle");

			uint8[] clear = OctagonCrypto.aes_256_gcm_decrypt (escrow.symmetric_key.get_data (),
				parsed.contents.initialization_vector.get_data (),
				parsed.contents.ciphertext.get_data (),
				parsed.contents.authentication_code.get_data ());

			var contents = OctagonBottleContents.parse (clear);

			if (!OctagonCrypto.verify (parsed.peer_signing_spki.get_data (), bottle, signature_using_peer))
				throw new Efni.Error.PROTOCOL ("Invalid peer signature on the bottle");

			return contents;
		}

		/**
		 * Recover the peer identity from a bottle fetched from Cuttlefish during escrow recovery,
		 * using the bottled entropy the escrow proxy handed back and the account altDSID as the
		 * key-derivation salt. Unlike {@link open}, the detached escrow and peer signatures are not
		 * carried by the fetchViableBottles response, so integrity rests on re-deriving the escrow
		 * keys (the escrowed SPKI must match) and the AES-GCM tag over the contents. The bottle is
		 * sealed under the altDSID, with an empty-salt fallback for records minted before the
		 * altDSID was known.
		 */
		public static OctagonBottleContents recover_identity (uint8[] bottle, uint8[] entropy,
				string altdsid) throws Efni.Error {
			try {
				return recover_with_salt (bottle, entropy, altdsid);
			} catch (Efni.Error first) {
				return recover_with_salt (bottle, entropy, "");
			}
		}

		private static OctagonBottleContents recover_with_salt (uint8[] bottle, uint8[] entropy,
				string salt) throws Efni.Error {
			var escrow = OctagonEscrowKeys.derive (entropy, salt);
			var parsed = parse (bottle);

			if (parsed.escrowed_signing_spki.compare (escrow.signing_spki) != 0)
				throw new Efni.Error.PROTOCOL ("Escrow entropy does not match the bottle");

			uint8[] clear = OctagonCrypto.aes_256_gcm_decrypt (escrow.symmetric_key.get_data (),
				parsed.contents.initialization_vector.get_data (),
				parsed.contents.ciphertext.get_data (),
				parsed.contents.authentication_code.get_data ());
			return OctagonBottleContents.parse (clear);
		}
	}

	/**
	 * The decrypted interior of a bottle: the peer's own signing and encryption private
	 * keys, which together are the Octagon peer identity.
	 */
	public sealed class OctagonBottleContents : Object {
		public OctagonPrivateKey peer_signing_key {
			get;
			construct;
		}

		public OctagonPrivateKey peer_encryption_key {
			get;
			construct;
		}

		public OctagonBottleContents (OctagonPrivateKey peer_signing_key,
				OctagonPrivateKey peer_encryption_key) {
			Object (peer_signing_key: peer_signing_key, peer_encryption_key: peer_encryption_key);
		}

		public static OctagonBottleContents parse (uint8[] data) throws Efni.Error {
			OctagonPrivateKey? peer_signing_key = null;
			OctagonPrivateKey? peer_encryption_key = null;

			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 3:
						peer_signing_key = OctagonPrivateKey.parse (reader.read_bytes ());
						break;
					case 4:
						peer_encryption_key = OctagonPrivateKey.parse (reader.read_bytes ());
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}

			if (peer_signing_key == null || peer_encryption_key == null)
				throw new Efni.Error.PROTOCOL ("Incomplete Octagon bottle contents");

			return new OctagonBottleContents (peer_signing_key, peer_encryption_key);
		}
	}

	/**
	 * A private key as a bottle carries it: a key type and the raw key bytes. Octagon
	 * uses NIST curve keys, whose bytes are the X9.63 encoding.
	 */
	public sealed class OctagonPrivateKey : Object {
		public const uint KEY_TYPE_EC_NIST_CURVES = 1;

		public uint key_type {
			get;
			construct;
		}

		public Bytes key_data {
			get;
			construct;
		}

		public OctagonPrivateKey (uint key_type, Bytes key_data) {
			Object (key_type: key_type, key_data: key_data);
		}

		public static OctagonPrivateKey parse (uint8[] data) throws Efni.Error {
			uint key_type = 0;
			Bytes? key_data = null;

			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						key_type = (uint) reader.read_varint ();
						break;
					case 2:
						key_data = new Bytes (reader.read_bytes ());
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}

			if (key_data == null)
				throw new Efni.Error.PROTOCOL ("Incomplete Octagon private key");

			return new OctagonPrivateKey (key_type, key_data);
		}
	}

	/**
	 * The AES-256-GCM ciphertext of a bottle's contents: the ciphertext, the GCM
	 * authentication tag, and the initialization vector that opened it.
	 */
	public sealed class OctagonAuthenticatedCiphertext : Object {
		public Bytes ciphertext {
			get;
			construct;
		}

		public Bytes authentication_code {
			get;
			construct;
		}

		public Bytes initialization_vector {
			get;
			construct;
		}

		public OctagonAuthenticatedCiphertext (Bytes ciphertext, Bytes authentication_code,
				Bytes initialization_vector) {
			Object (ciphertext: ciphertext, authentication_code: authentication_code,
				initialization_vector: initialization_vector);
		}

		public static OctagonAuthenticatedCiphertext parse (uint8[] data) throws Efni.Error {
			Bytes? ciphertext = null;
			Bytes? authentication_code = null;
			Bytes? initialization_vector = null;

			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						ciphertext = new Bytes (reader.read_bytes ());
						break;
					case 2:
						authentication_code = new Bytes (reader.read_bytes ());
						break;
					case 3:
						initialization_vector = new Bytes (reader.read_bytes ());
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}

			if (ciphertext == null || authentication_code == null || initialization_vector == null)
				throw new Efni.Error.PROTOCOL ("Incomplete Octagon authenticated ciphertext");

			return new OctagonAuthenticatedCiphertext (ciphertext, authentication_code,
				initialization_vector);
		}
	}
}
