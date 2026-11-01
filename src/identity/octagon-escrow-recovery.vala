using Efni;

namespace Idun {
	/**
	 * Drives escrow recovery end to end. The viable bottles — the encrypted Octagon peer
	 * identities the account has escrowed — live in Cuttlefish; the secret that unlocks one lives
	 * in the escrow proxy behind an SRP challenge keyed on the iCloud Security Code. Recovery
	 * fetches the bottles, proves the secret to the escrow proxy to recover the bottled entropy,
	 * and opens the matching bottle into the peer's signing and encryption private keys — the
	 * identity idun vouches with to join the Octagon trust circle.
	 *
	 * Recovery is IRREVERSIBLE: each attempt spends one of the escrow record's limited tries, so
	 * {@link recover} refuses to run without explicit confirmation.
	 */
	public sealed class OctagonEscrowRecovery : Object {
		public EscrowProxyClient escrow {
			get;
			construct;
		}

		public CloudKitClient cuttlefish {
			get;
			construct;
		}

		public OctagonEscrowRecovery (EscrowProxyClient escrow, CloudKitClient cuttlefish) {
			Object (escrow: escrow, cuttlefish: cuttlefish);
		}

		/**
		 * List the account's viable bottles. Non-destructive: it spends no escrow attempt and needs
		 * no secret, so idun can show the user which devices can be recovered before committing.
		 */
		public async Gee.List<OctagonViableBottle> fetch_viable_bottles (Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			Bytes response = yield cuttlefish.invoke ("fetchViableBottles",
				encode_fetch_viable_bottles_request (), cancellable);
			return parse_viable_bottles (response.get_data ());
		}

		/**
		 * Recover the Octagon peer identity from one viable bottle. Proves the secret to the escrow
		 * proxy for the bottle's record, then opens the bottle with the recovered entropy. Pass the
		 * bottle chosen from {@link fetch_viable_bottles}; the altDSID is the escrow key-derivation
		 * salt. IRREVERSIBLE — {@link confirm} must be set only once the secret is trusted.
		 */
		public async RecoveredOctagonPeer recover (OctagonViableBottle bottle, uint8[] secret,
				string altdsid, bool confirm, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			Bytes entropy = yield escrow.recover (bottle.record_label, secret, confirm, cancellable);

			var contents = OctagonBottle.recover_identity (bottle.bottle.get_data (),
				entropy.get_data (), altdsid);
			string peer_id = OctagonBottle.parse (bottle.bottle.get_data ()).peer_id;
			return new RecoveredOctagonPeer (peer_id, contents);
		}

		/**
		 * Fetch the account's Octagon trust graph. Non-destructive: it reads the circle's peers
		 * and the current trust policy without changing anything. A null sync token requests the
		 * full graph; the returned {@link OctagonTrustChanges.sync_token} advances a later
		 * incremental fetch.
		 */
		public async OctagonTrustChanges fetch_changes (string? sync_token = null,
				Cancellable? cancellable = null) throws Efni.Error, IOError {
			Bytes response = yield cuttlefish.invoke ("fetchChanges",
				OctagonTrustChanges.encode_request (sync_token), cancellable);
			return OctagonTrustChanges.parse (response.get_data ());
		}

		/**
		 * List the CKKS TLK shares a peer can recover. Non-destructive: it reads the account's
		 * shared key hierarchy without spending an escrow attempt. Pass the sponsor peer id whose
		 * keys the bottle recovers; the returned shares are the ones sealed to that peer, which
		 * {@link RecoverableTlkShare.unwrap} opens with the recovered encryption key.
		 */
		public async Gee.List<RecoverableTlkShare> fetch_recoverable_tlk_shares (string peer_id,
				Cancellable? cancellable = null) throws Efni.Error, IOError {
			Bytes response = yield cuttlefish.invoke ("fetchRecoverableTLKShares",
				encode_fetch_recoverable_tlkshares_request (peer_id), cancellable);
			return parse_recoverable_tlk_shares (response.get_data ());
		}

		public static Bytes encode_fetch_recoverable_tlkshares_request (string peer_id) {
			return new Bytes (new ProtobufWriter ().append_bytes (1, peer_id.data).data);
		}

		/**
		 * Join the trust circle with a vouched self-peer. DESTRUCTIVE: it writes idun's peer into
		 * the account's Octagon trust, so it runs only once the self-peer, the sponsor's voucher,
		 * and the circle's restore point (the fetchChanges sync token) are all in hand.
		 */
		public async void join_with_voucher (OctagonSelfPeer self, OctagonVoucher voucher,
				string restore_point, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			yield cuttlefish.invoke ("joinWithVoucher",
				encode_join_with_voucher_request (self.encode_for_join (voucher), restore_point),
				cancellable);
		}

		public static Bytes encode_join_with_voucher_request (uint8[] peer, string restore_point) {
			return new Bytes (new ProtobufWriter ()
				.append_bytes (1, restore_point.data)
				.append_bytes (2, peer)
				.data);
		}

		// The response lists per-view groups under field 1; each group's field 3 is a Cuttlefish
		// record wrapper whose field 2 is the serialized CloudKit record. The tlkshare records are
		// the shares; the sync-key records (under the group's field 2) are left for the key
		// hierarchy walk once a TLK is in hand.
		public static Gee.List<RecoverableTlkShare> parse_recoverable_tlk_shares (uint8[] response)
				throws Efni.Error {
			var shares = new Gee.ArrayList<RecoverableTlkShare> ();
			var reader = new ProtobufReader (response);
			while (reader.has_more) {
				uint8 wire_type;
				if (reader.read_field (out wire_type) == 1 && wire_type == 2)
					collect_tlk_share (reader.read_bytes (), shares);
				else
					reader.skip (wire_type);
			}
			return shares;
		}

		private static void collect_tlk_share (uint8[] group, Gee.List<RecoverableTlkShare> shares)
				throws Efni.Error {
			var reader = new ProtobufReader (group);
			while (reader.has_more) {
				uint8 wire_type;
				if (reader.read_field (out wire_type) == 3 && wire_type == 2) {
					uint8[]? record = extract_bottle (reader.read_bytes ());
					if (record == null)
						continue;
					var parsed = CloudKitRecord.parse (record);
					if (parsed.record_type == "tlkshare")
						shares.add (new RecoverableTlkShare (parsed));
				} else {
					reader.skip (wire_type);
				}
			}
		}

		public static Bytes encode_fetch_viable_bottles_request () {
			return new Bytes (new ProtobufWriter ()
				.append_varint (1, 1)
				.append_bytes (2, {})
				.data);
		}

		// Viable bottles are listed under field 1; each entry carries its record label (field 1)
		// and a wrapper (field 2) whose field 2 is the serialized OTBottle.
		public static Gee.List<OctagonViableBottle> parse_viable_bottles (uint8[] response)
				throws Efni.Error {
			var bottles = new Gee.ArrayList<OctagonViableBottle> ();
			var reader = new ProtobufReader (response);
			while (reader.has_more) {
				uint8 wire_type;
				if (reader.read_field (out wire_type) == 1 && wire_type == 2) {
					var bottle = parse_viable_entry (reader.read_bytes ());
					if (bottle != null)
						bottles.add (bottle);
				} else {
					reader.skip (wire_type);
				}
			}
			return bottles;
		}

		private static OctagonViableBottle? parse_viable_entry (uint8[] entry) throws Efni.Error {
			string record_label = "";
			uint8[]? bottle = null;
			var reader = new ProtobufReader (entry);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						record_label = reader.read_string ();
						break;
					case 2:
						bottle = extract_bottle (reader.read_bytes ());
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}
			if (bottle == null)
				return null;
			return new OctagonViableBottle (record_label, new Bytes (bottle));
		}

		private static uint8[]? extract_bottle (uint8[] wrapper) throws Efni.Error {
			uint8[]? bottle = null;
			var reader = new ProtobufReader (wrapper);
			while (reader.has_more) {
				uint8 wire_type;
				if (reader.read_field (out wire_type) == 2)
					bottle = reader.read_bytes ();
				else
					reader.skip (wire_type);
			}
			return bottle;
		}
	}

	/**
	 * One escrowed Octagon peer: the record label that names it to the escrow proxy and the
	 * serialized bottle that holds its encrypted keys.
	 */
	public sealed class OctagonViableBottle : Object {
		public string record_label {
			get;
			construct;
		}

		public Bytes bottle {
			get;
			construct;
		}

		public OctagonViableBottle (string record_label, Bytes bottle) {
			Object (record_label: record_label, bottle: bottle);
		}
	}

	/**
	 * A recovered Octagon peer identity: its peer id and the signing and encryption private keys
	 * idun uses to vouch for and establish itself as a trusted peer.
	 */
	public sealed class RecoveredOctagonPeer : Object {
		public string peer_id {
			get;
			construct;
		}

		public OctagonBottleContents contents {
			get;
			construct;
		}

		public RecoveredOctagonPeer (string peer_id, OctagonBottleContents contents) {
			Object (peer_id: peer_id, contents: contents);
		}

		/**
		 * Sign a voucher that sponsors a new peer into the trust circle. The recovered peer is the
		 * sponsor; {@link beneficiary_peer_id} is the joining peer idun built for itself. The
		 * voucher is what joinWithVoucher presents as proof that an already-trusted peer vouches
		 * for the newcomer.
		 */
		public OctagonVoucher make_voucher (string beneficiary_peer_id, int reason = 1)
				throws Efni.Error {
			uint8[] info = new ProtobufWriter ()
				.append_varint (1, reason)
				.append_bytes (2, beneficiary_peer_id.data)
				.append_bytes (3, peer_id.data)
				.data;
			uint8[] signature = OctagonPeerKeys.sign_prefixed (
				contents.peer_signing_key.key_data.get_data (), info,
				OctagonPeerKeys.VOUCHER_SIG_TYPE);
			return new OctagonVoucher (new Bytes (info), new Bytes (signature));
		}
	}

	/**
	 * A signed voucher: the encoded {reason, beneficiary, sponsor} and the sponsor's signature over
	 * it, the credential a joining peer carries into joinWithVoucher.
	 */
	public sealed class OctagonVoucher : Object {
		public Bytes info {
			get;
			construct;
		}

		public Bytes signature {
			get;
			construct;
		}

		public OctagonVoucher (Bytes info, Bytes signature) {
			Object (info: info, signature: signature);
		}
	}

	/**
	 * One recoverable CKKS TLK share: the key hierarchy's top-level key (the TLK), sealed to a
	 * peer's encryption key. The wrapped key is an Apple IESCiphertext keyed-archive; unwrapping
	 * it with the receiving peer's recovered encryption key yields the TLK uuid and bytes, which
	 * decrypt the synced keychain view the share belongs to.
	 */
	public sealed class RecoverableTlkShare : Object {
		public string record_name {
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

		private string wrapped_key;

		public RecoverableTlkShare (CloudKitRecord record) {
			Object (record_name: record.record_name,
				receiver_peer_id: record.string_field ("receiver") ?? "",
				sender_peer_id: record.string_field ("sender") ?? "");
			wrapped_key = record.string_field ("wrappedkey") ?? "";
		}

		/**
		 * Open the wrapped TLK with the receiving peer's X9.63 encryption private key. Decodes the
		 * IESCiphertext keyed-archive into its ephemeral public key, ciphertext, and tag, trims the
		 * trailing SecurityFoundation padding, and ECIES-decrypts to the TLK uuid and key.
		 */
		public void unwrap (uint8[] recipient_private_x963, out string uuid, out Bytes key)
				throws Efni.Error {
			uint8[] ephemeral, ciphertext, auth_code;
			decode_wrapped_key (out ephemeral, out ciphertext, out auth_code);
			OctagonPeerKeys.unwrap_tlk (recipient_private_x963, ephemeral, ciphertext, auth_code,
				out uuid, out key);
		}

		/**
		 * Decode the IESCiphertext keyed-archive into its ECIES components: the ephemeral sender
		 * public key, the (unpadded) ciphertext, and the authentication code.
		 */
		public void decode_wrapped_key (out uint8[] ephemeral, out uint8[] ciphertext,
				out uint8[] auth_code) throws Efni.Error {
			extract_ciphertext (Base64.decode (wrapped_key), out ephemeral, out ciphertext,
				out auth_code);
		}

		// SecurityFoundation appends 97 + 16 bytes after the real ciphertext in the stored blob.
		private const int CIPHERTEXT_PADDING = 97 + 16;

		// The wrapped key is an NSKeyedArchiver archive whose $top names three fields directly —
		// the ephemeral sender public key, the ciphertext, and the authentication code — each a
		// data object in $objects.
		private static void extract_ciphertext (uint8[] archive, out uint8[] ephemeral,
				out uint8[] ciphertext, out uint8[] auth_code) throws Efni.Error {
			try {
				var plist = new Plist.from_binary (archive);
				var objects = plist.get_array ("$objects");
				var top = plist.get_dict ("$top");

				ephemeral = data_object (objects,
					top.get_uid ("SFEphemeralSenderPublicKeyExternaRepresentation").uid);
				uint8[] stored = data_object (objects, top.get_uid ("SFCiphertext").uid);
				auth_code = data_object (objects, top.get_uid ("SFIESAuthenticationCode").uid);

				if (stored.length <= CIPHERTEXT_PADDING)
					throw new Efni.Error.PROTOCOL ("TLKShare ciphertext is too short to unpad");
				ciphertext = stored[0 : stored.length - CIPHERTEXT_PADDING];
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed TLKShare wrapped key: %s", e.message);
			}
		}

		// A $objects entry that holds data, stored either inline or as an NSData dictionary.
		private static uint8[] data_object (PlistArray objects, uint64 index)
				throws Efni.Error, PlistError {
			try {
				return objects.get_bytes ((int) index).get_data ();
			} catch (PlistError e) {
				return objects.get_dict ((int) index).get_bytes ("NS.data").get_data ();
			}
		}
	}
}
