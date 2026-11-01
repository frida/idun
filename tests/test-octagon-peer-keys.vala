using Efni;

namespace Idun.OctagonPeerKeysTest {
	public void add_tests () {
		GLib.Test.add_func ("/OctagonPeerKeys/voucher-round-trips", voucher_round_trips);
		GLib.Test.add_func ("/OctagonPeerKeys/tlkshare-unwraps", tlkshare_unwraps);
		GLib.Test.add_func ("/OctagonPeerKeys/peer-id-is-stable", peer_id_is_stable);
	}

	// The recovered sponsor signs a voucher for the joining peer; the signature must verify under
	// the sponsor's signing key with the Voucher domain-separation prefix, and reject tampering.
	private void voucher_round_trips () {
		try {
			uint8[] signing = OctagonPeerKeys.generate_private_x963 ();
			uint8[] encryption = OctagonPeerKeys.generate_private_x963 ();
			var contents = new OctagonBottleContents (
				new OctagonPrivateKey (OctagonPrivateKey.KEY_TYPE_EC_NIST_CURVES, new Bytes (signing)),
				new OctagonPrivateKey (OctagonPrivateKey.KEY_TYPE_EC_NIST_CURVES, new Bytes (encryption)));
			var sponsor = new RecoveredOctagonPeer ("SHA256:sponsor-peer", contents);

			var voucher = sponsor.make_voucher ("SHA256:joining-peer");
			uint8[] spki = OctagonPeerKeys.public_spki (signing).get_data ();

			assert_true (OctagonPeerKeys.verify_prefixed (spki, voucher.info.get_data (),
				voucher.signature.get_data (), OctagonPeerKeys.VOUCHER_SIG_TYPE));

			var tampered = voucher.info.get_data ();
			tampered[tampered.length - 1] ^= 0xff;
			assert_true (!OctagonPeerKeys.verify_prefixed (spki, tampered,
				voucher.signature.get_data (), OctagonPeerKeys.VOUCHER_SIG_TYPE));
		} catch (GLib.Error e) {
			GLib.error ("voucher round-trip failed: %s", e.message);
		}
	}

	// A TLKShare sealed to a peer's encryption key (ECIES over the CuttlefishSerializedKey) must
	// unwrap back to the TLK uuid and key bytes with that peer's private key.
	private void tlkshare_unwraps () {
		try {
			uint8[] recipient = OctagonPeerKeys.generate_private_x963 ();
			uint8[] recipient_public = recipient[0 : 97];

			uint8[] tlk = new uint8[32];
			for (int i = 0; i != tlk.length; i++)
				tlk[i] = (uint8) (i * 3 + 7);
			uint8[] serialized = new ProtobufWriter ()
				.append_bytes (1, "11112222-3333-4444-5555-666677778888".data)
				.append_bytes (4, tlk)
				.data;

			uint8[] ephemeral, ciphertext, auth_code;
			OctagonPeerKeys.ecies_encrypt (recipient_public, serialized, out ephemeral,
				out ciphertext, out auth_code);

			string uuid;
			Bytes key;
			OctagonPeerKeys.unwrap_tlk (recipient, ephemeral, ciphertext, auth_code, out uuid, out key);

			assert_true (uuid == "11112222-3333-4444-5555-666677778888");
			assert_true (key.compare (new Bytes (tlk)) == 0);
		} catch (GLib.Error e) {
			GLib.error ("tlkshare unwrap failed: %s", e.message);
		}
	}

	private void peer_id_is_stable () {
		uint8[] data = { 0x0a, 0x01, 0x02, 0x03 };
		uint8[] sig = { 0x30, 0x44, 0x02, 0x20 };
		string a = OctagonPeerKeys.derive_peer_id (data, sig);
		string b = OctagonPeerKeys.derive_peer_id (data, sig);
		assert_true (a == b);
		assert_true (a.has_prefix ("SHA256:"));
	}
}
