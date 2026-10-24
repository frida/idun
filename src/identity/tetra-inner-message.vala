using Efni;

namespace Idun {
	/**
	 * The plaintext a pair-tetra message carries once decrypted: the application
	 * payload, plus the optional key-transparency gossip a device piggybacks so peers
	 * can audit each other's published keys.
	 */
	public sealed class TetraInnerMessage : Object {
		public Bytes plaintext {
			get;
			construct;
		}

		public Bytes? kt_gossip_data {
			get;
			construct;
		}

		public TetraInnerMessage (Bytes plaintext, Bytes? kt_gossip_data = null) {
			Object (plaintext: plaintext, kt_gossip_data: kt_gossip_data);
		}

		public uint8[] serialize () {
			var writer = new ProtobufWriter ();
			writer.append_bytes (1, plaintext.get_data ());
			if (kt_gossip_data != null)
				writer.append_bytes (2, kt_gossip_data.get_data ());
			return writer.data;
		}

		public static TetraInnerMessage parse (uint8[] data) throws Efni.Error {
			Bytes? plaintext = null;
			Bytes? kt_gossip_data = null;

			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						plaintext = new Bytes (reader.read_bytes ());
						break;
					case 2:
						kt_gossip_data = new Bytes (reader.read_bytes ());
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}

			if (plaintext == null)
				throw new Efni.Error.PROTOCOL ("Incomplete pair-tetra inner message");

			return new TetraInnerMessage (plaintext, kt_gossip_data);
		}
	}
}
