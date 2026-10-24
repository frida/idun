using Efni;

namespace Idun {
	/**
	 * The outer envelope of a pair-tetra message: the ciphertext of the padded inner
	 * message, the sender's ephemeral ratchet key and signature that authenticate it,
	 * and the indices that place it in the ratchet. A fresh ratchet step also carries
	 * the Kyber encapsulation that mixes the post-quantum secret into the session.
	 */
	public sealed class TetraMessage : Object {
		public uint32 version {
			get;
			construct;
		}

		public Bytes ciphertext {
			get;
			construct;
		}

		public Bytes signature {
			get;
			construct;
		}

		public Bytes ecdh_public_key {
			get;
			construct;
		}

		public uint64 message_index {
			get;
			construct;
		}

		public Bytes message_key_indicator {
			get;
			construct;
		}

		public Bytes? kem_encapsulation {
			get;
			construct;
		}

		public Bytes? used_registered_keys {
			get;
			construct;
		}

		public TetraMessage (uint32 version, Bytes ciphertext, Bytes signature, Bytes ecdh_public_key,
				uint64 message_index, Bytes message_key_indicator, Bytes? kem_encapsulation = null,
				Bytes? used_registered_keys = null) {
			Object (version: version, ciphertext: ciphertext, signature: signature,
				ecdh_public_key: ecdh_public_key, message_index: message_index,
				message_key_indicator: message_key_indicator, kem_encapsulation: kem_encapsulation,
				used_registered_keys: used_registered_keys);
		}

		public uint8[] serialize () {
			var writer = new ProtobufWriter ();
			writer
				.append_varint (1, version)
				.append_bytes (2, ciphertext.get_data ())
				.append_bytes (3, signature.get_data ())
				.append_bytes (4, ecdh_public_key.get_data ());
			if (kem_encapsulation != null)
				writer.append_bytes (6, kem_encapsulation.get_data ());
			writer.append_varint (7, message_index);
			if (used_registered_keys != null)
				writer.append_bytes (8, used_registered_keys.get_data ());
			writer.append_bytes (9, message_key_indicator.get_data ());
			return writer.data;
		}

		public static TetraMessage parse (uint8[] data) throws Efni.Error {
			uint32 version = 0;
			Bytes? ciphertext = null;
			Bytes? signature = null;
			Bytes? ecdh_public_key = null;
			uint64 message_index = 0;
			Bytes? message_key_indicator = null;
			Bytes? kem_encapsulation = null;
			Bytes? used_registered_keys = null;

			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						version = (uint32) reader.read_varint ();
						break;
					case 2:
						ciphertext = new Bytes (reader.read_bytes ());
						break;
					case 3:
						signature = new Bytes (reader.read_bytes ());
						break;
					case 4:
						ecdh_public_key = new Bytes (reader.read_bytes ());
						break;
					case 6:
						kem_encapsulation = new Bytes (reader.read_bytes ());
						break;
					case 7:
						message_index = reader.read_varint ();
						break;
					case 8:
						used_registered_keys = new Bytes (reader.read_bytes ());
						break;
					case 9:
						message_key_indicator = new Bytes (reader.read_bytes ());
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}

			if (ciphertext == null || signature == null || ecdh_public_key == null ||
					message_key_indicator == null)
				throw new Efni.Error.PROTOCOL ("Incomplete pair-tetra message");

			return new TetraMessage (version, ciphertext, signature, ecdh_public_key, message_index,
				message_key_indicator, kem_encapsulation, used_registered_keys);
		}
	}
}
