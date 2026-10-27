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
		private uint8[] kem_encapsulation;
		private TetraRootContext context;
		private bool we_are_initiator;

		private const string START_DST = "TetraStart-";
		private const string RATCHET_DST = "TetraRatchet-";

		private TetraSession (Bytes signing_key) {
			this.signing_key = signing_key;
		}

		public static TetraSession establish_as_sender (Bytes signing_key, TetraRootContext context,
				uint8[] peer_ratchet_point, uint8[] peer_kyber_public) throws Efni.Error {
			var session = new TetraSession (signing_key);
			session.context = context;
			session.we_are_initiator = true;
			session.our_ratchet_key = TetraCrypto.generate_key_agreement_key ();
			session.our_ratchet_point = TetraCrypto.compact_point (
				TetraCrypto.public_key_point (session.our_ratchet_key));
			session.their_ratchet_point = peer_ratchet_point;

			uint8[] ecdh_secret = TetraCrypto.ecdh (session.our_ratchet_key,
				TetraCrypto.decompress_point (peer_ratchet_point));
			uint8[] encapsulation;
			uint8[] kem_secret = TetraCrypto.kyber_encapsulate (peer_kyber_public, out encapsulation);
			session.encapsulation_to_send = new Bytes (encapsulation);
			session.kem_encapsulation = encapsulation;

			uint8[] chain;
			TetraCrypto.derive_root_and_chain (new uint8[0], ecdh_secret, kem_secret,
				session.root_transcript (START_DST), out session.root_key, out chain);
			session.sending = new TetraSymmetricRatchet (chain);
			return session;
		}

		public static TetraSession establish_as_receiver (Bytes signing_key, TetraRootContext context,
				Bytes our_ratchet_key, uint8[] our_kyber_secret, uint8[] sender_ratchet_point,
				uint8[] encapsulation) throws Efni.Error {
			var session = new TetraSession (signing_key);
			session.context = context;
			session.we_are_initiator = false;
			session.our_ratchet_key = our_ratchet_key;
			session.our_ratchet_point = TetraCrypto.compact_point (
				TetraCrypto.public_key_point (our_ratchet_key));
			session.their_ratchet_point = sender_ratchet_point;
			session.kem_encapsulation = encapsulation;

			uint8[] ecdh_secret = TetraCrypto.ecdh (our_ratchet_key,
				TetraCrypto.decompress_point (sender_ratchet_point));
			uint8[] kem_secret = TetraCrypto.kyber_decapsulate (our_kyber_secret, encapsulation);

			uint8[] chain;
			TetraCrypto.derive_root_and_chain (new uint8[0], ecdh_secret, kem_secret,
				session.root_transcript (START_DST), out session.root_key, out chain);
			session.receiving = new TetraSymmetricRatchet (chain);
			session.sending_needs_step = true;
			return session;
		}

		/**
		 * Assemble the conversation DST for a root derivation. The ratchet points are the
		 * current ones, mapped onto initiator and responder by our role; everything else is
		 * the fixed registration binding. The label selects establishment versus a
		 * Diffie-Hellman ratchet step.
		 */
		private uint8[] root_transcript (string label) {
			uint8[] responder_point = we_are_initiator ? their_ratchet_point : our_ratchet_point;
			uint8[] initiator_point = we_are_initiator ? our_ratchet_point : their_ratchet_point;
			return TetraCrypto.build_root_transcript (
				context.initiator_uri.get_data (),
				context.initiator_push_token.get_data (),
				context.initiator_signing.get_data (),
				context.responder_uri.get_data (),
				context.responder_push_token.get_data (),
				context.responder_signing.get_data (),
				label,
				responder_point,
				initiator_point,
				kem_encapsulation,
				context.responder_kyber_public.get_data ());
		}

		public uint8[] message_key_indicator (uint64 index) throws Efni.Error {
			return TetraCrypto.derive_message_key_indicator (receiving.message_key_for (index));
		}

		public uint8[] seal (uint8[] plaintext, uint8[] topic, TetraBinding[] bindings)
				throws Efni.Error {
			if (sending_needs_step)
				step_sending ();

			uint64 index;
			uint8[] message_key = sending.advance (out index);

			Bytes? encapsulation = encapsulation_to_send;
			encapsulation_to_send = null;
			uint8[] encapsulation_data = encapsulation != null ? encapsulation.get_data () : new uint8[0];
			uint8[] authenticated_data = TetraCrypto.build_authenticated_data (topic,
				TetraCrypto.derive_message_key_indicator (message_key), our_ratchet_point, index,
				bindings, encapsulation_data, new uint8[0]);
			return TetraCrypto.seal_message (message_key, signing_key, our_ratchet_point, index,
				plaintext, authenticated_data, encapsulation);
		}

		public uint8[] open (uint8[] message, uint8[] sender_signing_point, uint8[] topic,
				TetraBinding[] bindings, bool verify = true) throws Efni.Error {
			var parsed = TetraMessage.parse (message);

			uint8[] their_point = parsed.ecdh_public_key.get_data ();
			if (new Bytes (their_point).compare (new Bytes (their_ratchet_point)) != 0)
				step_receiving (their_point);

			uint8[] message_key = receiving.message_key_for (parsed.message_index);
			uint8[] encapsulation = parsed.kem_encapsulation != null
				? parsed.kem_encapsulation.get_data () : new uint8[0];
			uint8[] used_registered_keys = parsed.used_registered_keys != null
				? parsed.used_registered_keys.get_data () : new uint8[0];
			uint8[] authenticated_data = TetraCrypto.build_authenticated_data (topic,
				parsed.message_key_indicator.get_data (), their_point, parsed.message_index, bindings,
				encapsulation, used_registered_keys);
			return TetraCrypto.open_message (message_key, sender_signing_point, message,
				authenticated_data, verify);
		}

		public uint8[] serialize () {
			var writer = new ProtobufWriter ();
			writer
				.append_bytes (1, signing_key.get_data ())
				.append_bytes (2, root_key)
				.append_bytes (3, our_ratchet_key.get_data ())
				.append_bytes (4, our_ratchet_point)
				.append_bytes (5, their_ratchet_point);
			if (sending != null)
				writer.append_bytes (6, sending.serialize ());
			if (receiving != null)
				writer.append_bytes (7, receiving.serialize ());
			writer.append_varint (8, sending_needs_step ? 1 : 0);
			if (encapsulation_to_send != null)
				writer.append_bytes (9, encapsulation_to_send.get_data ());
			writer.append_bytes (10, context.serialize ());
			writer.append_varint (11, we_are_initiator ? 1 : 0);
			writer.append_bytes (12, kem_encapsulation);
			return writer.data;
		}

		public static TetraSession restore (uint8[] data) throws Efni.Error {
			Bytes? signing_key = null;
			uint8[]? root_key = null;
			Bytes? our_ratchet_key = null;
			uint8[]? our_ratchet_point = null;
			uint8[]? their_ratchet_point = null;
			TetraSymmetricRatchet? sending = null;
			TetraSymmetricRatchet? receiving = null;
			bool sending_needs_step = false;
			Bytes? encapsulation = null;
			TetraRootContext? context = null;
			bool we_are_initiator = false;
			uint8[]? kem_encapsulation = null;

			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						signing_key = new Bytes (reader.read_bytes ());
						break;
					case 2:
						root_key = reader.read_bytes ();
						break;
					case 3:
						our_ratchet_key = new Bytes (reader.read_bytes ());
						break;
					case 4:
						our_ratchet_point = reader.read_bytes ();
						break;
					case 5:
						their_ratchet_point = reader.read_bytes ();
						break;
					case 6:
						sending = TetraSymmetricRatchet.restore (reader.read_bytes ());
						break;
					case 7:
						receiving = TetraSymmetricRatchet.restore (reader.read_bytes ());
						break;
					case 8:
						sending_needs_step = reader.read_varint () != 0;
						break;
					case 9:
						encapsulation = new Bytes (reader.read_bytes ());
						break;
					case 10:
						context = TetraRootContext.restore (reader.read_bytes ());
						break;
					case 11:
						we_are_initiator = reader.read_varint () != 0;
						break;
					case 12:
						kem_encapsulation = reader.read_bytes ();
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}

			if (signing_key == null || root_key == null || our_ratchet_key == null ||
					our_ratchet_point == null || their_ratchet_point == null || context == null ||
					kem_encapsulation == null)
				throw new Efni.Error.PROTOCOL ("Incomplete pair-tetra session state");

			var session = new TetraSession (signing_key);
			session.context = context;
			session.we_are_initiator = we_are_initiator;
			session.kem_encapsulation = kem_encapsulation;
			session.root_key = root_key;
			session.our_ratchet_key = our_ratchet_key;
			session.our_ratchet_point = our_ratchet_point;
			session.their_ratchet_point = their_ratchet_point;
			session.sending = sending;
			session.receiving = receiving;
			session.sending_needs_step = sending_needs_step;
			session.encapsulation_to_send = encapsulation;
			return session;
		}

		private void step_sending () throws Efni.Error {
			our_ratchet_key = TetraCrypto.generate_key_agreement_key ();
			our_ratchet_point = TetraCrypto.compact_point (
				TetraCrypto.public_key_point (our_ratchet_key));

			uint8[] ecdh_secret = TetraCrypto.ecdh (our_ratchet_key,
				TetraCrypto.decompress_point (their_ratchet_point));
			uint8[] chain;
			TetraCrypto.derive_root_and_chain (root_key, ecdh_secret, null,
				root_transcript (RATCHET_DST), out root_key, out chain);
			sending = new TetraSymmetricRatchet (chain);
			sending_needs_step = false;
		}

		private void step_receiving (uint8[] their_point) throws Efni.Error {
			their_ratchet_point = their_point;

			uint8[] ecdh_secret = TetraCrypto.ecdh (our_ratchet_key,
				TetraCrypto.decompress_point (their_point));
			uint8[] chain;
			TetraCrypto.derive_root_and_chain (root_key, ecdh_secret, null,
				root_transcript (RATCHET_DST), out root_key, out chain);
			receiving = new TetraSymmetricRatchet (chain);
			sending_needs_step = true;
		}
	}
}
