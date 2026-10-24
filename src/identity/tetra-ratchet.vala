using Efni;

namespace Idun {
	/**
	 * One direction of a pair-tetra symmetric ratchet: a chain key that yields a fresh
	 * message key for each message and advances past it, so a compromised message key
	 * never exposes earlier or later ones. A sender steps it forward per message; a
	 * receiver steps its own copy up to the index a message carries.
	 */
	public sealed class TetraSymmetricRatchet : Object {
		private uint8[] chain_key;
		private uint64 next_index;

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

		public uint8[] message_key_for (uint64 target_index) throws Efni.Error {
			if (target_index < next_index)
				throw new Efni.Error.PROTOCOL ("Pair-tetra message key already consumed");

			uint8[] message_key = {};
			uint64 reached = 0;
			do {
				message_key = advance (out reached);
			} while (reached < target_index);
			return message_key;
		}
	}
}
