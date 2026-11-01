using Efni;

namespace Idun {
	/**
	 * The Octagon trust graph as Cuttlefish returns it from fetchChanges: the set of peers in the
	 * account's circle, each carrying its signed permanent, stable, and dynamic info, plus the
	 * sync token that advances an incremental fetch. Joining the circle needs this graph twice
	 * over — to read the account's current trust policy (which every peer's stable info carries)
	 * and to read the sponsor's dynamic info (the list of peers idun must include when it vouches
	 * itself in).
	 */
	public sealed class OctagonTrustChanges : Object {
		public string sync_token {
			get;
			construct;
		}

		public Gee.List<OctagonPeerRecord> peers {
			get;
			construct;
		}

		public OctagonTrustChanges (string sync_token, Gee.List<OctagonPeerRecord> peers) {
			Object (sync_token: sync_token, peers: peers);
		}

		/**
		 * The account's current trust policy, read from any peer that carries stable info. Every
		 * trusted peer advertises the same frozen and flexible policy, so the joining peer must
		 * stamp these exact versions and hashes into its own stable info or the circle rejects it.
		 */
		public OctagonPolicy? current_policy () throws Efni.Error {
			foreach (var peer in peers) {
				if (peer.stable_info == null)
					continue;
				var stable = OctagonStableInfo.parse (peer.stable_info.info.get_data ());
				if (stable.frozen_policy_hash != "" && stable.flexible_policy_hash != "")
					return new OctagonPolicy (stable.frozen_policy_version,
						stable.frozen_policy_hash, stable.flexible_policy_version,
						stable.flexible_policy_hash);
			}
			return null;
		}

		/**
		 * Compute the trust state a peer vouched by the given sponsor must adopt: the included
		 * set (the sponsor's trusted peers), the next stable clock (one past the highest stable
		 * clock in the circle), and the next dynamic clock (one past the sponsor's). This mirrors
		 * how an already-trusted peer would advance the circle when it admits a newcomer.
		 */
		public void compute_trust (string sponsor_peer_id, out Gee.List<string> included,
				out uint64 stable_clock, out uint64 dynamic_clock) throws Efni.Error {
			included = new Gee.ArrayList<string> ();
			uint64 max_stable = 0;
			uint64 sponsor_dynamic = 0;
			foreach (var peer in peers) {
				if (peer.stable_info != null) {
					uint64 clock = OctagonStableInfo.parse (peer.stable_info.info.get_data ()).clock;
					if (clock > max_stable)
						max_stable = clock;
				}
				if (peer.peer_id == sponsor_peer_id && peer.dynamic_info != null) {
					var di = OctagonDynamicInfo.parse (peer.dynamic_info.info.get_data ());
					included = di.included;
					sponsor_dynamic = di.clock;
				}
			}
			stable_clock = max_stable + 1;
			dynamic_clock = sponsor_dynamic + 1;
		}

		/**
		 * The peer record for a given peer id, or null when the graph does not carry it.
		 */
		public OctagonPeerRecord? peer_for_id (string peer_id) {
			foreach (var peer in peers) {
				if (peer.peer_id == peer_id)
					return peer;
			}
			return null;
		}

		public static Bytes encode_request (string? sync_token) {
			var writer = new ProtobufWriter ();
			if (sync_token != null && sync_token != "")
				writer.append_bytes (1, sync_token.data);
			return new Bytes (writer.data);
		}

		// The result wraps the changes in field 1: a sync token (field 1) and the repeated changes
		// (field 2). Each change carries the added peer under field 3.
		public static OctagonTrustChanges parse (uint8[] result) throws Efni.Error {
			uint8[]? changes = null;
			var reader = new ProtobufReader (result);
			while (reader.has_more) {
				uint8 wire_type;
				if (reader.read_field (out wire_type) == 1 && wire_type == 2)
					changes = reader.read_bytes ();
				else
					reader.skip (wire_type);
			}
			if (changes == null)
				return new OctagonTrustChanges ("", new Gee.ArrayList<OctagonPeerRecord> ());

			string sync_token = "";
			var peers = new Gee.ArrayList<OctagonPeerRecord> ();
			var changes_reader = new ProtobufReader (changes);
			while (changes_reader.has_more) {
				uint8 wire_type;
				switch (changes_reader.read_field (out wire_type)) {
					case 1:
						sync_token = changes_reader.read_string ();
						break;
					case 2:
						var peer = parse_change (changes_reader.read_bytes ());
						if (peer != null)
							peers.add (peer);
						break;
					default:
						changes_reader.skip (wire_type);
						break;
				}
			}
			return new OctagonTrustChanges (sync_token, peers);
		}

		private static OctagonPeerRecord? parse_change (uint8[] change) throws Efni.Error {
			var reader = new ProtobufReader (change);
			while (reader.has_more) {
				uint8 wire_type;
				if (reader.read_field (out wire_type) == 3 && wire_type == 2)
					return parse_peer (reader.read_bytes ());
				reader.skip (wire_type);
			}
			return null;
		}

		private static OctagonPeerRecord parse_peer (uint8[] peer) throws Efni.Error {
			string peer_id = "";
			OctagonSignedInfo? permanent = null;
			OctagonSignedInfo? stable = null;
			OctagonSignedInfo? dynamic_blob = null;
			OctagonSignedInfo? voucher = null;

			var reader = new ProtobufReader (peer);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						peer_id = reader.read_string ();
						break;
					case 2:
						permanent = OctagonSignedInfo.parse (reader.read_bytes ());
						break;
					case 3:
						stable = OctagonSignedInfo.parse (reader.read_bytes ());
						break;
					case 4:
						dynamic_blob = OctagonSignedInfo.parse (reader.read_bytes ());
						break;
					case 5:
						voucher = OctagonSignedInfo.parse (reader.read_bytes ());
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}
			return new OctagonPeerRecord (peer_id, permanent, stable, dynamic_blob, voucher);
		}
	}

	/**
	 * One peer in the trust graph: its peer id and the signed info structures that describe it.
	 * Each info is kept as its raw signed form so its signature can be verified and, for the
	 * joining peer's own records, re-encoded.
	 */
	public sealed class OctagonPeerRecord : Object {
		public string peer_id {
			get;
			construct;
		}

		public OctagonSignedInfo? permanent_info {
			get;
			construct;
		}

		public OctagonSignedInfo? stable_info {
			get;
			construct;
		}

		public OctagonSignedInfo? dynamic_info {
			get;
			construct;
		}

		public OctagonSignedInfo? voucher {
			get;
			construct;
		}

		public OctagonPeerRecord (string peer_id, OctagonSignedInfo? permanent_info,
				OctagonSignedInfo? stable_info, OctagonSignedInfo? dynamic_info,
				OctagonSignedInfo? voucher) {
			Object (peer_id: peer_id, permanent_info: permanent_info, stable_info: stable_info,
				dynamic_info: dynamic_info, voucher: voucher);
		}
	}

	/**
	 * A signed Octagon structure: the serialized info (field 1) and the signature over it
	 * (field 2). The signature covers the type-prefixed info, so verification goes through
	 * {@link OctagonPeerKeys.verify_prefixed} with the matching signature type.
	 */
	public sealed class OctagonSignedInfo : Object {
		public Bytes info {
			get;
			construct;
		}

		public Bytes signature {
			get;
			construct;
		}

		public OctagonSignedInfo (Bytes info, Bytes signature) {
			Object (info: info, signature: signature);
		}

		public static OctagonSignedInfo parse (uint8[] data) throws Efni.Error {
			var info = new Bytes ({});
			var signature = new Bytes ({});
			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						info = new Bytes (reader.read_bytes ());
						break;
					case 2:
						signature = new Bytes (reader.read_bytes ());
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}
			return new OctagonSignedInfo (info, signature);
		}
	}

	/**
	 * The account's trust policy versions and hashes: the frozen policy (fixed per major release)
	 * and the flexible policy (bumped as Apple revises the trust rules). A joining peer copies
	 * these into its stable info so the circle accepts it under the same policy everyone else runs.
	 */
	public sealed class OctagonPolicy : Object {
		public uint64 frozen_version {
			get;
			construct;
		}

		public string frozen_hash {
			get;
			construct;
		}

		public uint64 flexible_version {
			get;
			construct;
		}

		public string flexible_hash {
			get;
			construct;
		}

		public OctagonPolicy (uint64 frozen_version, string frozen_hash, uint64 flexible_version,
				string flexible_hash) {
			Object (frozen_version: frozen_version, frozen_hash: frozen_hash,
				flexible_version: flexible_version, flexible_hash: flexible_hash);
		}
	}

	/**
	 * A peer's stable info: the account-level state a peer advertises, most importantly the trust
	 * policy it runs under and the device identity it presents. Idun reads a sponsor's stable info
	 * to learn the policy it must match when it builds its own.
	 */
	public sealed class OctagonStableInfo : Object {
		public uint64 clock {
			get;
			construct;
		}

		public uint64 frozen_policy_version {
			get;
			construct;
		}

		public string frozen_policy_hash {
			get;
			construct;
		}

		public uint64 flexible_policy_version {
			get;
			construct;
		}

		public string flexible_policy_hash {
			get;
			construct;
		}

		public string os_version {
			get;
			construct;
		}

		public string serial_number {
			get;
			construct;
		}

		public uint64 user_controllable_views {
			get;
			construct;
		}

		public OctagonStableInfo (uint64 clock, uint64 frozen_policy_version,
				string frozen_policy_hash, uint64 flexible_policy_version,
				string flexible_policy_hash, string os_version, string serial_number,
				uint64 user_controllable_views) {
			Object (clock: clock, frozen_policy_version: frozen_policy_version,
				frozen_policy_hash: frozen_policy_hash,
				flexible_policy_version: flexible_policy_version,
				flexible_policy_hash: flexible_policy_hash, os_version: os_version,
				serial_number: serial_number, user_controllable_views: user_controllable_views);
		}

		public static OctagonStableInfo parse (uint8[] data) throws Efni.Error {
			uint64 clock = 0;
			uint64 frozen_version = 0;
			string frozen_hash = "";
			uint64 flexible_version = 0;
			string flexible_hash = "";
			string os_version = "";
			string serial_number = "";
			uint64 ucv = 0;

			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						clock = reader.read_varint ();
						break;
					case 2:
						frozen_version = reader.read_varint ();
						break;
					case 3:
						frozen_hash = reader.read_string ();
						break;
					case 5:
						os_version = reader.read_string ();
						break;
					case 9:
						serial_number = reader.read_string ();
						break;
					case 10:
						flexible_version = reader.read_varint ();
						break;
					case 11:
						flexible_hash = reader.read_string ();
						break;
					case 12:
						ucv = reader.read_varint ();
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}
			return new OctagonStableInfo (clock, frozen_version, frozen_hash, flexible_version,
				flexible_hash, os_version, serial_number, ucv);
		}
	}

	/**
	 * A peer's dynamic info: the mutable trust decision — the peer ids it includes in the circle
	 * and the ones it excludes — plus the clock that orders those decisions. Idun reads the
	 * sponsor's included set to know which peers to carry forward when it vouches itself in.
	 */
	public sealed class OctagonDynamicInfo : Object {
		public uint64 clock {
			get;
			construct;
		}

		public Gee.List<string> included {
			get;
			construct;
		}

		public Gee.List<string> excluded {
			get;
			construct;
		}

		public OctagonDynamicInfo (uint64 clock, Gee.List<string> included,
				Gee.List<string> excluded) {
			Object (clock: clock, included: included, excluded: excluded);
		}

		public static OctagonDynamicInfo parse (uint8[] data) throws Efni.Error {
			uint64 clock = 0;
			var included = new Gee.ArrayList<string> ();
			var excluded = new Gee.ArrayList<string> ();

			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						clock = reader.read_varint ();
						break;
					case 2:
						included.add (reader.read_string ());
						break;
					case 3:
						excluded.add (reader.read_string ());
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}
			return new OctagonDynamicInfo (clock, included, excluded);
		}
	}
}
