using Efni;

namespace Idun {
	/**
	 * The Octagon peer identity idun builds for itself to join the trust circle. Joining does not
	 * reuse the recovered sponsor's keys: idun generates its own signing and encryption keys and
	 * describes itself with three signed structures — the permanent info (its keys and device
	 * identity, which fixes its peer id), the stable info (the trust policy it runs under, copied
	 * from the circle), and the dynamic info (the peers it trusts). The recovered sponsor then
	 * signs a voucher for this peer's id, and joinWithVoucher presents the peer and the voucher
	 * together.
	 */
	public sealed class OctagonSelfPeer : Object {
		public string peer_id {
			get;
			construct;
		}

		public Bytes signing_key {
			get;
			construct;
		}

		public Bytes encryption_key {
			get;
			construct;
		}

		private Bytes permanent_info;
		private Bytes permanent_signature;
		private Bytes stable_info;
		private Bytes stable_signature;
		private Bytes dynamic_info;
		private Bytes dynamic_signature;

		private OctagonSelfPeer (string peer_id, Bytes signing_key, Bytes encryption_key) {
			Object (peer_id: peer_id, signing_key: signing_key, encryption_key: encryption_key);
		}

		/**
		 * Generate a fresh peer identity and sign its three info structures. The policy is the
		 * circle's current {@link OctagonPolicy} (from {@link OctagonTrustChanges.current_policy}),
		 * the clocks come from the trust computation over the fetched changes, and the trusted set
		 * is the sponsor's included peers with this new peer added. The user-controllable-view
		 * status mirrors the circle so the joining peer runs the same view policy as its peers.
		 */
		public static OctagonSelfPeer generate (OctagonPolicy policy, string machine_id,
				string model_id, string serial_number, string os_version, uint64 stable_clock,
				uint64 dynamic_clock, Gee.List<string> trusted_peer_ids,
				uint64 user_controllable_views, int64 creation_time = 0) throws Efni.Error {
			Bytes signing = new Bytes (OctagonPeerKeys.generate_private_x963 ());
			Bytes encryption = new Bytes (OctagonPeerKeys.generate_private_x963 ());

			int64 created = (creation_time != 0) ? creation_time : new DateTime.now_utc ().to_unix ();
			uint8[] permanent = new ProtobufWriter ()
				.append_varint (1, 1)
				.append_bytes (2, OctagonPeerKeys.public_spki (signing.get_data ()).get_data ())
				.append_bytes (3, OctagonPeerKeys.public_spki (encryption.get_data ()).get_data ())
				.append_bytes (4, machine_id.data)
				.append_bytes (5, model_id.data)
				.append_varint (6, created)
				.data;
			uint8[] permanent_sig = OctagonPeerKeys.sign_prefixed (signing.get_data (), permanent,
				OctagonPeerKeys.PERMANENT_INFO_SIG_TYPE);
			string peer_id = OctagonPeerKeys.derive_peer_id (permanent, permanent_sig);

			uint8[] stable = new ProtobufWriter ()
				.append_varint (1, stable_clock)
				.append_varint (2, policy.frozen_version)
				.append_bytes (3, policy.frozen_hash.data)
				.append_bytes (5, os_version.data)
				.append_bytes (6, "".data)
				.append_bytes (9, serial_number.data)
				.append_varint (10, policy.flexible_version)
				.append_bytes (11, policy.flexible_hash.data)
				.append_varint (12, user_controllable_views)
				.append_varint (19, 1)
				.data;
			uint8[] stable_sig = OctagonPeerKeys.sign_prefixed (signing.get_data (), stable,
				OctagonPeerKeys.STABLE_INFO_SIG_TYPE);

			var included = new Gee.ArrayList<string> ();
			foreach (var id in trusted_peer_ids) {
				if (!included.contains (id))
					included.add (id);
			}
			if (!included.contains (peer_id))
				included.add (peer_id);

			var dynamic_writer = new ProtobufWriter ().append_varint (1, dynamic_clock);
			foreach (var id in included)
				dynamic_writer.append_bytes (2, id.data);
			uint8[] dynamic = dynamic_writer.data;
			uint8[] dynamic_sig = OctagonPeerKeys.sign_prefixed (signing.get_data (), dynamic,
				OctagonPeerKeys.DYNAMIC_INFO_SIG_TYPE);

			var self = new OctagonSelfPeer (peer_id, signing, encryption);
			self.permanent_info = new Bytes (permanent);
			self.permanent_signature = new Bytes (permanent_sig);
			self.stable_info = new Bytes (stable);
			self.stable_signature = new Bytes (stable_sig);
			self.dynamic_info = new Bytes (dynamic);
			self.dynamic_signature = new Bytes (dynamic_sig);
			return self;
		}

		/**
		 * Encode the peer for joinWithVoucher: the peer id and the three signed infos, with the
		 * sponsor's voucher attached as the fifth field.
		 */
		public uint8[] encode_for_join (OctagonVoucher voucher) {
			return new ProtobufWriter ()
				.append_bytes (1, peer_id.data)
				.append_bytes (2, signed_info (permanent_info, permanent_signature))
				.append_bytes (3, signed_info (stable_info, stable_signature))
				.append_bytes (4, signed_info (dynamic_info, dynamic_signature))
				.append_bytes (5, signed_info (voucher.info, voucher.signature))
				.data;
		}

		/**
		 * The peer's signing SubjectPublicKeyInfo, which verifiers use to check the three infos'
		 * signatures (and which the peer id commits to through the permanent info).
		 */
		public Bytes signing_spki () throws Efni.Error {
			return OctagonPeerKeys.public_spki (signing_key.get_data ());
		}

		public Bytes permanent_info_data () {
			return permanent_info;
		}

		public Bytes stable_info_data () {
			return stable_info;
		}

		public Bytes dynamic_info_data () {
			return dynamic_info;
		}

		private static uint8[] signed_info (Bytes info, Bytes signature) {
			return new ProtobufWriter ()
				.append_bytes (1, info.get_data ())
				.append_bytes (2, signature.get_data ())
				.data;
		}
	}
}
