using Efni;

namespace Idun {
	/**
	 * A pair-tetra session between two devices: the root the key agreement established,
	 * the sending and receiving symmetric ratchets, and the Diffie-Hellman ratchet that
	 * refreshes them. Each message carries the sender's current ratchet key; receiving a
	 * new one, or sending after a receive, steps the root forward so the chains keep
	 * moving even if one is compromised. A sender derives the session from the peer's
	 * prekey and carries the Kyber encapsulation in its first message; the receiver
	 * rebuilds it from that.
	 */
	public sealed class TetraSession : Object {
		private Bytes signing_key;
		private uint8[] root_key;
		private Bytes our_ratchet_key;
		private uint8[] our_ratchet_point;
		private uint8[] their_ratchet_point;
		private TetraSymmetricRatchet? sending;
		private TetraSymmetricRatchet? receiving;
		private bool sending_needs_step;
		private Bytes? encapsulation_to_send;

		private const string RATCHET_DST = "TetraRatchet-";

		private TetraSession (Bytes signing_key) {
			this.signing_key = signing_key;
		}

		public static TetraSession establish_as_sender (Bytes signing_key, uint8[] peer_ratchet_point,
				uint8[] peer_kyber_public) throws Efni.Error {
			var session = new TetraSession (signing_key);
			session.our_ratchet_key = TetraCrypto.generate_key_agreement_key ();
			session.our_ratchet_point = TetraCrypto.compact_point (
				TetraCrypto.public_key_point (session.our_ratchet_key));
			session.their_ratchet_point = peer_ratchet_point;

			uint8[] ecdh_secret = TetraCrypto.ecdh (session.our_ratchet_key,
				TetraCrypto.decompress_point (peer_ratchet_point));
			uint8[] encapsulation;
			uint8[] kem_secret = TetraCrypto.kyber_encapsulate (peer_kyber_public, out encapsulation);
			session.encapsulation_to_send = new Bytes (encapsulation);

			uint8[] chain;
			TetraCrypto.derive_root_and_chain (new uint8[0], ecdh_secret, kem_secret, RATCHET_DST.data,
				out session.root_key, out chain);
			session.sending = new TetraSymmetricRatchet (chain);
			return session;
		}

		public static TetraSession establish_as_receiver (Bytes signing_key, Bytes our_ratchet_key,
				uint8[] our_kyber_secret, uint8[] sender_ratchet_point, uint8[] encapsulation)
				throws Efni.Error {
			var session = new TetraSession (signing_key);
			session.our_ratchet_key = our_ratchet_key;
			session.our_ratchet_point = TetraCrypto.compact_point (
				TetraCrypto.public_key_point (our_ratchet_key));
			session.their_ratchet_point = sender_ratchet_point;

			uint8[] ecdh_secret = TetraCrypto.ecdh (our_ratchet_key,
				TetraCrypto.decompress_point (sender_ratchet_point));
			uint8[] kem_secret = TetraCrypto.kyber_decapsulate (our_kyber_secret, encapsulation);

			uint8[] chain;
			TetraCrypto.derive_root_and_chain (new uint8[0], ecdh_secret, kem_secret, RATCHET_DST.data,
				out session.root_key, out chain);
			session.receiving = new TetraSymmetricRatchet (chain);
			session.sending_needs_step = true;
			return session;
		}

		public uint8[] seal (uint8[] plaintext, uint8[] authenticated_data) throws Efni.Error {
			if (sending_needs_step)
				step_sending ();

			uint64 index;
			uint8[] message_key = sending.advance (out index);

			Bytes? encapsulation = encapsulation_to_send;
			encapsulation_to_send = null;
			return TetraCrypto.seal_message (message_key, signing_key, our_ratchet_point, index,
				plaintext, authenticated_data, encapsulation);
		}

		public uint8[] open (uint8[] message, uint8[] sender_signing_point, uint8[] authenticated_data)
				throws Efni.Error {
			var parsed = TetraMessage.parse (message);

			uint8[] their_point = parsed.ecdh_public_key.get_data ();
			if (new Bytes (their_point).compare (new Bytes (their_ratchet_point)) != 0)
				step_receiving (their_point);

			uint8[] message_key = receiving.message_key_for (parsed.message_index);
			return TetraCrypto.open_message (message_key, sender_signing_point, message,
				authenticated_data);
		}

		private void step_sending () throws Efni.Error {
			our_ratchet_key = TetraCrypto.generate_key_agreement_key ();
			our_ratchet_point = TetraCrypto.compact_point (
				TetraCrypto.public_key_point (our_ratchet_key));

			uint8[] ecdh_secret = TetraCrypto.ecdh (our_ratchet_key,
				TetraCrypto.decompress_point (their_ratchet_point));
			uint8[] chain;
			TetraCrypto.derive_root_and_chain (root_key, ecdh_secret, null, RATCHET_DST.data,
				out root_key, out chain);
			sending = new TetraSymmetricRatchet (chain);
			sending_needs_step = false;
		}

		private void step_receiving (uint8[] their_point) throws Efni.Error {
			their_ratchet_point = their_point;

			uint8[] ecdh_secret = TetraCrypto.ecdh (our_ratchet_key,
				TetraCrypto.decompress_point (their_point));
			uint8[] chain;
			TetraCrypto.derive_root_and_chain (root_key, ecdh_secret, null, RATCHET_DST.data,
				out root_key, out chain);
			receiving = new TetraSymmetricRatchet (chain);
			sending_needs_step = true;
		}
	}
}
