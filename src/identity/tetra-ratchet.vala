using Efni;

namespace Idun {
	/**
	 * One direction of a pair-tetra symmetric ratchet: a chain key that yields a fresh
	 * message key for each message and advances past it, so a compromised message key
	 * never exposes earlier or later ones. A sender steps it forward per message; a
	 * receiver steps its copy up to the index a message carries, keeping the keys it
	 * stepped over so a message that arrives out of order can still be opened.
	 */
	public sealed class TetraSymmetricRatchet : Object {
		private uint8[] chain_key;
		private uint64 next_index;
		private Gee.HashMap<string, Bytes> skipped = new Gee.HashMap<string, Bytes> ();

		public uint64 index {
			get {
				return next_index;
			}
		}

		public TetraSymmetricRatchet (uint8[] chain_key, uint64 index = 0) {
			this.chain_key = chain_key;
			this.next_index = index;
		}

		public uint8[] advance (out uint64 message_index) throws Efni.Error {
			message_index = next_index;
			uint8[] message_key = TetraCrypto.derive_message_key (chain_key);
			chain_key = TetraCrypto.advance_chain_key (chain_key);
			next_index++;
			return message_key;
		}

		public uint8[] serialize () {
			var writer = new ProtobufWriter ();
			writer.append_bytes (1, chain_key);
			writer.append_varint (2, next_index);
			foreach (var entry in skipped.entries) {
				uint8[] pair = new ProtobufWriter ()
					.append_varint (1, uint64.parse (entry.key))
					.append_bytes (2, entry.value.get_data ())
					.data;
				writer.append_bytes (3, pair);
			}
			return writer.data;
		}

		public static TetraSymmetricRatchet restore (uint8[] data) throws Efni.Error {
			uint8[]? chain_key = null;
			uint64 next_index = 0;
			var skipped = new Gee.HashMap<string, Bytes> ();

			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						chain_key = reader.read_bytes ();
						break;
					case 2:
						next_index = reader.read_varint ();
						break;
					case 3:
						uint64 skipped_index = 0;
						Bytes? key = null;
						var pair = new ProtobufReader (reader.read_bytes ());
						while (pair.has_more) {
							uint8 pair_wire;
							switch (pair.read_field (out pair_wire)) {
								case 1:
									skipped_index = pair.read_varint ();
									break;
								case 2:
									key = new Bytes (pair.read_bytes ());
									break;
								default:
									pair.skip (pair_wire);
									break;
							}
						}
						if (key != null)
							skipped[skipped_index.to_string ()] = key;
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}

			if (chain_key == null)
				throw new Efni.Error.PROTOCOL ("Incomplete pair-tetra ratchet state");

			var ratchet = new TetraSymmetricRatchet (chain_key, next_index);
			ratchet.skipped = skipped;
			return ratchet;
		}

		public uint8[] message_key_for (uint64 target_index) throws Efni.Error {
			if (target_index < next_index) {
				Bytes? cached = skipped[target_index.to_string ()];
				if (cached == null)
					throw new Efni.Error.PROTOCOL ("Pair-tetra message key already consumed");
				skipped.unset (target_index.to_string ());
				return cached.get_data ();
			}

			while (next_index < target_index) {
				uint64 skipped_index;
				uint8[] message_key = advance (out skipped_index);
				skipped[skipped_index.to_string ()] = new Bytes (message_key);
			}

			uint64 index;
			return advance (out index);
		}
	}
}
