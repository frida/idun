using Efni;

namespace Idun {
	/**
	 * A pair-tetra session between two devices: the shared root the key agreement
	 * established, and the two symmetric ratchets that seal our outgoing messages and
	 * open the peer's. A sender derives it from the peer's published prekey and carries
	 * the ratchet key and Kyber encapsulation in its first message; the receiver
	 * rebuilds the same session from those.
	 */
	public sealed class TetraSession : Object {
		private Bytes signing_key;
		private uint8[] sending_key_point;
		private Bytes? encapsulation_to_send;
		private TetraSymmetricRatchet? sending;
		private TetraSymmetricRatchet? receiving;

		private const string RATCHET_DST = "TetraRatchet-";

		private TetraSession (Bytes signing_key) {
			this.signing_key = signing_key;
		}

		public static TetraSession establish_as_sender (Bytes signing_key, uint8[] peer_ecdh_point,
				uint8[] peer_kyber_public) throws Efni.Error {
			var session = new TetraSession (signing_key);

			Bytes ephemeral = TetraCrypto.generate_key_agreement_key ();
			session.sending_key_point = TetraCrypto.public_key_point (ephemeral);

			uint8[] ecdh_secret = TetraCrypto.ecdh (ephemeral, peer_ecdh_point);
			uint8[] encapsulation;
			uint8[] kem_secret = TetraCrypto.kyber_encapsulate (peer_kyber_public, out encapsulation);
			session.encapsulation_to_send = new Bytes (encapsulation);

			uint8[] root, chain;
			TetraCrypto.derive_root_and_chain (new uint8[32], ecdh_secret, kem_secret, RATCHET_DST.data,
				out root, out chain);
			session.sending = new TetraSymmetricRatchet (chain);
			return session;
		}

		public static TetraSession establish_as_receiver (Bytes signing_key, Bytes our_ecdh_key,
				uint8[] our_kyber_secret, uint8[] sender_key_point, uint8[] encapsulation)
				throws Efni.Error {
			var session = new TetraSession (signing_key);

			uint8[] ecdh_secret = TetraCrypto.ecdh (our_ecdh_key, sender_key_point);
			uint8[] kem_secret = TetraCrypto.kyber_decapsulate (our_kyber_secret, encapsulation);

			uint8[] root, chain;
			TetraCrypto.derive_root_and_chain (new uint8[32], ecdh_secret, kem_secret, RATCHET_DST.data,
				out root, out chain);
			session.receiving = new TetraSymmetricRatchet (chain);
			return session;
		}

		public uint8[] seal (uint8[] plaintext, uint8[] authenticated_data) throws Efni.Error {
			uint64 index;
			uint8[] message_key = sending.advance (out index);

			Bytes? encapsulation = encapsulation_to_send;
			encapsulation_to_send = null;
			return TetraCrypto.seal_message (message_key, signing_key, sending_key_point, index,
				plaintext, authenticated_data, encapsulation);
		}

		public uint8[] open (uint8[] message, Bytes sender_signing_key, uint8[] authenticated_data)
				throws Efni.Error {
			var parsed = TetraMessage.parse (message);
			uint8[] message_key = receiving.message_key_for (parsed.message_index);
			return TetraCrypto.open_message (message_key, sender_signing_key, message, authenticated_data);
		}
	}
}
