using Efni;

namespace Idun {
	/**
	 * A CKKS TLK share: the top-level keychain-sync key (the TLK) wrapped so one trusted
	 * Octagon peer can hand it to another. The share names the sending and receiving peers,
	 * carries the wrapped TLK, and is signed by the sender so the receiver can trust it
	 * before unwrapping. Recovering the TLK lets Idun decrypt the synced keychain items,
	 * including the account key-transparency key it signs its registration with.
	 */
	public sealed class CkksTlkShare : Object {
		public uint64 version {
			get;
			construct;
		}

		public string receiver_peer_id {
			get;
			construct;
		}

		public string sender_peer_id {
			get;
			construct;
		}

		public Bytes wrapped_tlk {
			get;
			construct;
		}

		public uint64 curve {
			get;
			construct;
		}

		public uint64 epoch {
			get;
			construct;
		}

		public uint64 poisoned {
			get;
			construct;
		}

		public Bytes signature {
			get;
			construct;
		}

		public CkksTlkShare (uint64 version, string receiver_peer_id, string sender_peer_id,
				Bytes wrapped_tlk, uint64 curve, uint64 epoch, uint64 poisoned, Bytes signature) {
			Object (version: version, receiver_peer_id: receiver_peer_id, sender_peer_id: sender_peer_id,
				wrapped_tlk: wrapped_tlk, curve: curve, epoch: epoch, poisoned: poisoned,
				signature: signature);
		}

		/**
		 * The bytes a share's signature covers: the version, the receiving and sending peer
		 * ids, the wrapped TLK, and the curve, epoch, and poisoned flags, with every integer
		 * encoded little-endian. The receiver's public key is deliberately excluded.
		 */
		public uint8[] data_for_signing () {
			var data = new ByteArray ();
			data.append (little_endian (version));
			data.append (receiver_peer_id.data);
			data.append (sender_peer_id.data);
			data.append (wrapped_tlk.get_data ());
			data.append (little_endian (curve));
			data.append (little_endian (epoch));
			data.append (little_endian (poisoned));
			return data.data;
		}

		public bool verify (uint8[] sender_signing_spki) throws Efni.Error {
			return OctagonCrypto.verify (sender_signing_spki, data_for_signing (),
				signature.get_data (), "SHA256");
		}

		private static uint8[] little_endian (uint64 value) {
			var bytes = new uint8[8];
			for (int i = 0; i != 8; i++)
				bytes[i] = (uint8) (value >> (8 * i));
			return bytes;
		}
	}
}
