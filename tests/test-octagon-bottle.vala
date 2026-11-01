using Efni;

namespace Idun.OctagonBottleTest {
	public void add_tests () {
		GLib.Test.add_func ("/OctagonBottle/round-trips", round_trips);
		GLib.Test.add_func ("/OctagonBottle/rejects-wrong-secret", rejects_wrong_secret);
		GLib.Test.add_func ("/OctagonBottle/empty-salt-fallback", empty_salt_fallback);
		GLib.Test.add_func ("/OctagonEscrowRecovery/parses-viable-bottles", parses_viable_bottles);
		GLib.Test.add_func ("/CloudKitResponse/unwraps-function-result", unwraps_function_result);
		GLib.Test.add_func ("/RecoverableTlkShare/parses-and-decodes-real-wrappedkey",
			parses_and_decodes_real_wrappedkey);
		GLib.Test.add_func ("/OctagonTrust/parses-changes-policy-and-trust",
			parses_changes_policy_and_trust);
		GLib.Test.add_func ("/OctagonSelfPeer/builds-signed-vouched-peer",
			builds_signed_vouched_peer);
		GLib.Test.add_func ("/OctagonCrypto/aes-siv-multi-aad-roundtrips", aes_siv_multi_aad);
		GLib.Test.add_func ("/CkksKeychain/decrypts-item-from-tlk", decrypts_item_from_tlk);
		GLib.Test.add_func ("/KtAccountKey/signs-device-key-signature", signs_device_key_signature);
		GLib.Test.add_func ("/OctagonCrypto/aes-kw-unwrap-rfc3394", aes_kw_unwrap_rfc3394);
		GLib.Test.add_func ("/OctagonCrypto/aes-gcm-decrypt-kat", aes_gcm_decrypt_kat);
		GLib.Test.add_func ("/PcsMasterKey/decrypts-v3-roundtrip", pcs_v3_roundtrip);
		GLib.Test.add_func ("/OctagonEscrowRecord/parses", escrow_record_parses);
		GLib.Test.add_func ("/CloudKitCodeFunctionInvoke/round-trips", function_invoke_round_trips);
		GLib.Test.add_func ("/CkksTlkShare/signature-round-trips", tlk_share_signature);
	}

	private void tlk_share_signature () {
		try {
			var signer = OctagonEscrowKeys.derive (new uint8[72], "salt-for-signer");
			var share = new CkksTlkShare (0, "receiver-peer", "sender-peer",
				new Bytes ({ 0xaa, 0xbb, 0xcc }), 2, 1, 0, new Bytes ({}));
			uint8[] sig = OctagonCrypto.sign (signer.signing_key, share.data_for_signing (), "SHA256");
			var signed = new CkksTlkShare (0, "receiver-peer", "sender-peer",
				new Bytes ({ 0xaa, 0xbb, 0xcc }), 2, 1, 0, new Bytes (sig));
			assert_true (signed.verify (signer.signing_spki.get_data ()));
			var tampered = new CkksTlkShare (0, "receiver-peer", "ATTACKER-peer",
				new Bytes ({ 0xaa, 0xbb, 0xcc }), 2, 1, 0, new Bytes (sig));
			assert_true (!tampered.verify (signer.signing_spki.get_data ()));
		} catch (GLib.Error e) {
			GLib.error ("tlk share signature failed: %s", e.message);
		}
	}

	private void function_invoke_round_trips () {
		var req = new CloudKitCodeFunctionInvokeRequest ("fetchViableBottles", "Cuttlefish",
			new Bytes ({ 0x08, 0x01 }));
		try {
			var back = CloudKitCodeFunctionInvokeRequest.parse (req.serialize ());
			assert_true (back.function_name == "fetchViableBottles");
			assert_true (back.service_name == "Cuttlefish");
			assert_true (back.serialized_parameters.length == 2);
		} catch (GLib.Error e) {
			GLib.error ("function-invoke round-trip failed: %s", e.message);
		}
	}

	private void escrow_record_parses () {
		uint8[] metadata = new ProtobufWriter ()
			.append_bytes (4, "the-bottle-id".data)
			.append_bytes (6, { 0x30, 0x59, 0x01, 0x02 })
			.append_bytes (9, "C02ABC".data)
			.data;
		uint8[] record = new ProtobufWriter ()
			.append_varint (2, 9)
			.append_bytes (3, metadata)
			.append_bytes (11, "record-123".data)
			.append_bytes (14, "C02ABC".data)
			.data;
		try {
			var parsed = OctagonEscrowRecord.parse (record);
			assert_true (parsed.record_id == "record-123");
			assert_true (parsed.remaining_attempts == 9);
			assert_true (parsed.metadata.bottle_id == "the-bottle-id");
			assert_true (parsed.metadata.serial == "C02ABC");
			assert_true (parsed.metadata.escrowed_spki.length == 4);
		} catch (GLib.Error e) {
			GLib.error ("escrow record parse failed: %s", e.message);
		}
	}

	private void round_trips () {
		try {
			var recovered = open_sample_bottle (sample_secret ());
			assert_true (((string) recovered.peer_signing_key.key_data.get_data ()) == "peer-signing");
			assert_true (((string) recovered.peer_encryption_key.key_data.get_data ()) == "peer-encryption");
			assert_true (recovered.peer_signing_key.key_type == OctagonPrivateKey.KEY_TYPE_EC_NIST_CURVES);
		} catch (GLib.Error e) {
			GLib.error ("round-trip failed: %s", e.message);
		}
	}

	private void rejects_wrong_secret () {
		var wrong = sample_secret ();
		wrong[0] ^= 0xff;
		try {
			open_sample_bottle (wrong);
			GLib.error ("open accepted a wrong escrow secret");
		} catch (GLib.Error e) {
		}
	}

	// A bottle whose records were minted before the altDSID was known is sealed under an empty
	// salt; open_for_account must fall back from the account altDSID to "" and still recover it.
	private void empty_salt_fallback () {
		try {
			uint8[] bottle, signature_using_escrow, signature_using_peer;
			build_sample_bottle (sample_secret (), "", out bottle, out signature_using_escrow,
				out signature_using_peer);
			var recovered = OctagonBottle.recover_identity (bottle, sample_secret (),
				"001967-10-WRONG-ALTDSID");
			assert_true (((string) recovered.peer_signing_key.key_data.get_data ()) == "peer-signing");
		} catch (GLib.Error e) {
			GLib.error ("empty-salt fallback failed: %s", e.message);
		}
	}

	// A synthetic fetchViableBottles response wrapping one real bottle; confirm the parser pulls
	// the record label and the serialized bottle out of the nested framing, and that the extracted
	// bottle recovers end to end with the entropy that sealed it.
	private void parses_viable_bottles () {
		try {
			string altdsid = "00000000-TEST-0000-0000-000000000000";
			uint8[] entropy = sample_secret ();
			uint8[] bottle, sig_escrow, sig_peer;
			build_sample_bottle (entropy, altdsid, out bottle, out sig_escrow, out sig_peer);

			uint8[] wrapper = new ProtobufWriter ().append_bytes (2, bottle).data;
			uint8[] entry = new ProtobufWriter ()
				.append_bytes (1, "the-record-label".data)
				.append_bytes (2, wrapper)
				.data;
			uint8[] response = new ProtobufWriter ().append_bytes (1, entry).data;

			var bottles = OctagonEscrowRecovery.parse_viable_bottles (response);
			assert_true (bottles.size == 1);
			assert_true (bottles[0].record_label == "the-record-label");
			assert_true (bottles[0].bottle.compare (new Bytes (bottle)) == 0);

			var recovered = OctagonBottle.recover_identity (bottles[0].bottle.get_data (), entropy,
				altdsid);
			assert_true (((string) recovered.peer_signing_key.key_data.get_data ()) == "peer-signing");
		} catch (GLib.Error e) {
			GLib.error ("viable-bottles parse failed: %s", e.message);
		}
	}

	// The code router frames a function result as a length-delimited response operation whose
	// field 1101 holds the function-invoke response, whose field 1 is the serialized result. The
	// unwrap must peel exactly those three layers, matching the live CloudKit framing.
	private void unwraps_function_result () {
		try {
			uint8[] result = { 0x0a, 0x03, 0x61, 0x62, 0x63 };
			uint8[] invoke_response = new ProtobufWriter ().append_bytes (1, result).data;
			uint8[] operation = new ProtobufWriter ()
				.append_bytes (2, "op-uuid".data)
				.append_bytes (1101, invoke_response)
				.data;
			var framed = new ByteArray ();
			uint64 length = operation.length;
			do {
				uint8 piece = (uint8) (length & 0x7f);
				length >>= 7;
				if (length != 0)
					piece |= 0x80;
				framed.append ({ piece });
			} while (length != 0);
			framed.append (operation);

			uint8[] unwrapped = CloudKitRequestOperation.parse_function_result (framed.data);
			assert_true (new Bytes (unwrapped).compare (new Bytes (result)) == 0);
		} catch (GLib.Error e) {
			GLib.error ("function-result unwrap failed: %s", e.message);
		}
	}

	// A real fetchRecoverableTLKShares tlkshare record's wrappedkey, captured live from CloudKit:
	// an NSKeyedArchiver IESCiphertext whose $top names the ephemeral key, ciphertext, and auth
	// code directly. The parser must find the tlkshare record through the response framing and
	// decode the archive into a 97-byte P-384 point, the unpadded ciphertext, and a 16-byte tag.
	private const string REAL_WRAPPED_KEY =
		"YnBsaXN0MDDUAQIDBAUGBw5YJHZlcnNpb25ZJGFyY2hpdmVyVCR0b3BYJG9iamVjdHMSAAGGoF8QD05T" +
		"S2V5ZWRBcmNoaXZlctMICQoLDA1fEBdTRklFU0F1dGhlbnRpY2F0aW9uQ29kZVxTRkNpcGhlcnRleHRf" +
		"EC9TRkVwaGVtZXJhbFNlbmRlclB1YmxpY0tleUV4dGVybmFSZXByZXNlbnRhdGlvboAEgAGAAqUPEBEW" +
		"HVUkbnVsbE8Q5ECwbiyRhWH0HiFsGmkd9spvvrflKnc4dvFcHfnvu4ZTSLwEyTBDfSzGbrME/V1fihjh" +
		"B5hYgacWXlwvUdkJgSSSOvY+qqWoeW/4OTo1AFL9yzkZ5qlBY/i5RHoVxYGblXbN6eO4EPewk9c4vSBh" +
		"lNSbjVYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANIS" +
		"ExQVV05TLmRhdGFWJGNsYXNzTxBhBCRkSUvHQI4ZSuxWwE8avrMqNHjPI6Y78KxZI5ZK1++Ni1SzIXry" +
		"30UokQijvvbwRxGrZNSSFpFvctgp6kqsVrRphyfhxN/jphpMw3iTpTHez+CAL5dCxB+rGakURUV+H4AD" +
		"0hcYGRpaJGNsYXNzbmFtZVgkY2xhc3Nlc11OU011dGFibGVEYXRhoxkbHFZOU0RhdGFYTlNPYmplY3RP" +
		"EBCchwogyS1xzd8EMyJl60M5AAgAEQAaACQAKQAyADcASQBQAGoAdwCpAKsArQCvALUAuwGiAacBrwG2" +
		"AhoCHAIhAiwCNQJDAkcCTgJXAAAAAAAAAgEAAAAAAAAAHgAAAAAAAAAAAAAAAAAAAmo=";

	private void parses_and_decodes_real_wrappedkey () {
		try {
			string receiver = "SHA256:HLEBQDYwoTl7ZL6aWb+rYXDhQ90G2Wq8qKyjJMVeVac=";
			uint8[] record = build_ckks_record ("tlkshare-UUID::peer::peer", "tlkshare",
				receiver, REAL_WRAPPED_KEY);
			uint8[] cuttlefish_record = new ProtobufWriter ().append_bytes (2, record).data;
			uint8[] group = new ProtobufWriter ().append_bytes (3, cuttlefish_record).data;
			uint8[] response = new ProtobufWriter ().append_bytes (1, group).data;

			var shares = OctagonEscrowRecovery.parse_recoverable_tlk_shares (response);
			assert_true (shares.size == 1);
			assert_true (shares[0].receiver_peer_id == receiver);

			uint8[] ephemeral, ciphertext, auth_code;
			shares[0].decode_wrapped_key (out ephemeral, out ciphertext, out auth_code);
			assert_true (ephemeral.length == 97);
			assert_true (ephemeral[0] == 0x04);
			assert_true (auth_code.length == 16);
			assert_true (ciphertext.length == 115);
		} catch (GLib.Error e) {
			GLib.error ("tlkshare parse/decode failed: %s", e.message);
		}
	}

	// The fetchChanges result nests the trust graph three deep: changes{ sync_token, change[] },
	// each change{ add = peer }, each peer{ id, signed permanent/stable/dynamic info }. The parser
	// must pull the sync token, read the policy out of a peer's stable info, and read the included
	// set out of a peer's dynamic info.
	private void parses_changes_policy_and_trust () {
		try {
			string sponsor = "SHA256:sponsor";
			uint8[] stable_info = new ProtobufWriter ()
				.append_varint (1, 94)
				.append_varint (2, 5)
				.append_bytes (3, "SHA256:frozen-hash".data)
				.append_bytes (5, "macOS 27.0.0 (26A428)".data)
				.append_bytes (9, "K712WF0XY0".data)
				.append_varint (10, 23)
				.append_bytes (11, "SHA256:flex-hash".data)
				.data;
			uint8[] dynamic_info = new ProtobufWriter ()
				.append_varint (1, 42)
				.append_bytes (2, "SHA256:sponsor".data)
				.append_bytes (2, "SHA256:other".data)
				.append_bytes (3, "SHA256:kicked".data)
				.data;
			uint8[] peer = new ProtobufWriter ()
				.append_bytes (1, sponsor.data)
				.append_bytes (3, signed_info (stable_info))
				.append_bytes (4, signed_info (dynamic_info))
				.data;
			uint8[] changes = new ProtobufWriter ()
				.append_bytes (1, "sync-token-1".data)
				.append_bytes (2, new ProtobufWriter ().append_bytes (3, peer).data)
				.data;
			uint8[] result = new ProtobufWriter ().append_bytes (1, changes).data;

			var graph = OctagonTrustChanges.parse (result);
			assert_true (graph.sync_token == "sync-token-1");
			assert_true (graph.peers.size == 1);
			assert_true (graph.peers[0].peer_id == sponsor);

			var policy = graph.current_policy ();
			assert_true (policy != null);
			assert_true (policy.frozen_version == 5);
			assert_true (policy.frozen_hash == "SHA256:frozen-hash");
			assert_true (policy.flexible_version == 23);
			assert_true (policy.flexible_hash == "SHA256:flex-hash");

			var sponsor_peer = graph.peer_for_id (sponsor);
			var di = OctagonDynamicInfo.parse (sponsor_peer.dynamic_info.info.get_data ());
			assert_true (di.clock == 42);
			assert_true (di.included.size == 2);
			assert_true (di.included[0] == "SHA256:sponsor");
			assert_true (di.excluded.size == 1);
		} catch (GLib.Error e) {
			GLib.error ("trust-changes parse failed: %s", e.message);
		}
	}

	// The joining self-peer must generate its own keys, stamp the circle's policy into a signed
	// stable info, trust the sponsor's set plus itself in a signed dynamic info, derive its peer id
	// from the signed permanent info, and carry a voucher the recovered sponsor signs for that id.
	// Encode it as joinWithVoucher would, parse it back, and verify every signature end to end.
	private void builds_signed_vouched_peer () {
		try {
			uint8[] sponsor_signing = OctagonPeerKeys.generate_private_x963 ();
			uint8[] sponsor_encryption = OctagonPeerKeys.generate_private_x963 ();
			var sponsor = new RecoveredOctagonPeer ("SHA256:sponsor", new OctagonBottleContents (
				new OctagonPrivateKey (OctagonPrivateKey.KEY_TYPE_EC_NIST_CURVES,
					new Bytes (sponsor_signing)),
				new OctagonPrivateKey (OctagonPrivateKey.KEY_TYPE_EC_NIST_CURVES,
					new Bytes (sponsor_encryption))));

			var policy = new OctagonPolicy (5, "SHA256:frozen-hash", 23, "SHA256:flex-hash");
			var trusted = new Gee.ArrayList<string> ();
			trusted.add ("SHA256:sponsor");
			trusted.add ("SHA256:other");

			var self = OctagonSelfPeer.generate (policy, "machine-1", "Mac17,2", "SERIAL123",
				"macOS 27.0.0 (26A428)", 95, 95, trusted, 2, 1700000000);
			assert_true (self.peer_id.has_prefix ("SHA256:"));

			var voucher = sponsor.make_voucher (self.peer_id);
			uint8[] peer = self.encode_for_join (voucher);

			uint8[] changes = new ProtobufWriter ()
				.append_bytes (1, "token".data)
				.append_bytes (2, new ProtobufWriter ().append_bytes (3, peer).data)
				.data;
			var graph = OctagonTrustChanges.parse (
				new ProtobufWriter ().append_bytes (1, changes).data);
			assert_true (graph.peers.size == 1);
			var pr = graph.peers[0];
			assert_true (pr.peer_id == self.peer_id);

			uint8[] self_spki = self.signing_spki ().get_data ();
			assert_true (OctagonPeerKeys.verify_prefixed (self_spki, pr.permanent_info.info.get_data (),
				pr.permanent_info.signature.get_data (), OctagonPeerKeys.PERMANENT_INFO_SIG_TYPE));
			assert_true (OctagonPeerKeys.verify_prefixed (self_spki, pr.stable_info.info.get_data (),
				pr.stable_info.signature.get_data (), OctagonPeerKeys.STABLE_INFO_SIG_TYPE));
			assert_true (OctagonPeerKeys.verify_prefixed (self_spki, pr.dynamic_info.info.get_data (),
				pr.dynamic_info.signature.get_data (), OctagonPeerKeys.DYNAMIC_INFO_SIG_TYPE));

			assert_true (OctagonPeerKeys.derive_peer_id (pr.permanent_info.info.get_data (),
				pr.permanent_info.signature.get_data ()) == self.peer_id);

			var si = OctagonStableInfo.parse (pr.stable_info.info.get_data ());
			assert_true (si.frozen_policy_version == 5 && si.flexible_policy_version == 23);
			assert_true (si.flexible_policy_hash == "SHA256:flex-hash");
			assert_true (si.user_controllable_views == 2);

			var di = OctagonDynamicInfo.parse (pr.dynamic_info.info.get_data ());
			assert_true (di.included.contains ("SHA256:sponsor"));
			assert_true (di.included.contains (self.peer_id));

			uint8[] sponsor_spki = OctagonPeerKeys.public_spki (sponsor_signing).get_data ();
			assert_true (OctagonPeerKeys.verify_prefixed (sponsor_spki, pr.voucher.info.get_data (),
				pr.voucher.signature.get_data (), OctagonPeerKeys.VOUCHER_SIG_TYPE));
		} catch (GLib.Error e) {
			GLib.error ("self-peer build failed: %s", e.message);
		}
	}

	private void aes_siv_multi_aad () {
		try {
			var key = new uint8[64];
			for (int i = 0; i != key.length; i++)
				key[i] = (uint8) (i + 1);
			uint8[] plaintext = "the account KT signing key".data;
			var aad = new Bytes[] {
				new Bytes ("aaaabbbbccccdddd".data), new Bytes ("UUID-VALUE".data),
				new Bytes ({ 0x02, 0, 0, 0, 0, 0, 0, 0 }), new Bytes ({ 0, 0, 0, 0, 0, 0, 0, 0 }),
				new Bytes ("parent-key-id".data)
			};
			uint8[] wrapped = OctagonCrypto.aes_siv_encrypt (key, plaintext, aad);
			uint8[] recovered = OctagonCrypto.aes_siv_decrypt (key, wrapped, aad);
			assert_true (new Bytes (recovered).compare (new Bytes (plaintext)) == 0);

			var wrong = new Bytes[] { new Bytes ("aaaabbbbccccdddd".data) };
			try {
				OctagonCrypto.aes_siv_decrypt (key, wrapped, wrong);
				assert_not_reached ();
			} catch (GLib.Error e) {
			}
		} catch (GLib.Error e) {
			GLib.error ("aes-siv round-trip failed: %s", e.message);
		}
	}

	private void aes_gcm_decrypt_kat () {
		try {
			uint8[] key = from_hex ("feffe9928665731c6d6a8f9467308308");
			uint8[] iv = from_hex ("cafebabefacedbaddecaf888");
			uint8[] aad = from_hex ("feedfacedeadbeeffeedfacedeadbeefabaddad2");
			uint8[] ct = from_hex ("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
				+ "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091");
			uint8[] tag = from_hex ("5bc94fbc3221a5db94fae95ae7121a47");
			uint8[] expected = from_hex ("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a"
				+ "318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");

			uint8[] pt = OctagonCrypto.aes_gcm_decrypt (key, iv, ct, tag, aad);
			assert_true (new Bytes (pt).compare (new Bytes (expected)) == 0);
		} catch (GLib.Error e) {
			GLib.error ("aes-gcm KAT failed: %s", e.message);
		}
	}

	private void pcs_v3_roundtrip () {
		try {
			var raw = new uint8[16];
			for (int i = 0; i != raw.length; i++)
				raw[i] = (uint8) (i * 7 + 1);
			var master = new PcsMasterKey (new Bytes (raw));

			uint8[] key_id = master.key_id ().get_data ();
			uint8[] plaintext = "the account KT private key material".data;
			uint8[] iv = from_hex ("000102030405060708090a0b");

			int n = 4;
			var header = new ByteArray ();
			header.append ({ 0x03, key_id[0], key_id[1], (uint8) n });
			header.append (key_id[2 : 2 + n]);

			uint8[] tag16;
			uint8[] ct = OctagonCrypto.aes_gcm_encrypt (pcs_derive (raw, "encryption key key m"), iv,
				plaintext, header.data, out tag16);

			var ciphertext = new ByteArray ();
			ciphertext.append (header.data);
			ciphertext.append (iv);
			ciphertext.append (tag16[0 : 12]);
			ciphertext.append (ct);

			uint8[] recovered = master.decrypt (ciphertext.data, new uint8[0]);
			assert_true (new Bytes (recovered).compare (new Bytes (plaintext)) == 0);
		} catch (GLib.Error e) {
			GLib.error ("pcs v3 round-trip failed: %s", e.message);
		}
	}

	private uint8[] pcs_derive (uint8[] raw, string label) {
		var suffix = new ByteArray ();
		suffix.append (label.data);
		suffix.append ({ 0x00 });
		uint32 bits = (uint32) raw.length * 8;
		suffix.append ({ (uint8) (bits >> 24), (uint8) (bits >> 16), (uint8) (bits >> 8), (uint8) bits });

		var block = new ByteArray ();
		block.append ({ 0, 0, 0, 1 });
		block.append (suffix.data);

		var hmac = new Hmac (ChecksumType.SHA256, raw);
		hmac.update (block.data);
		var digest = new uint8[32];
		size_t len = digest.length;
		hmac.get_digest (digest, ref len);
		return digest[0 : raw.length];
	}

	private void aes_kw_unwrap_rfc3394 () {
		try {
			uint8[] kek = from_hex ("000102030405060708090a0b0c0d0e0f");
			uint8[] wrapped = from_hex ("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");
			uint8[] expected = from_hex ("00112233445566778899aabbccddeeff");
			uint8[] got = OctagonCrypto.aes_kw_unwrap (kek, wrapped);
			assert_true (new Bytes (got).compare (new Bytes (expected)) == 0);
		} catch (GLib.Error e) {
			GLib.error ("aes-kw unwrap failed: %s", e.message);
		}
	}

	private void signs_device_key_signature () {
		try {
			var scalar = new uint8[32];
			for (int i = 0; i != scalar.length; i++)
				scalar[i] = (uint8) (i * 5 + 3);
			uint8[] point = PcsKey.public_point (scalar);
			uint8[] x963 = new uint8[point.length + scalar.length];
			Memory.copy (x963, point, point.length);
			Memory.copy ((uint8 *) x963 + point.length, scalar, scalar.length);

			var kt = new KtAccountKey (new Bytes (x963));

			var sha1 = new Checksum (ChecksumType.SHA1);
			sha1.update (point, point.length);
			assert_true (kt.account_key_id ().compare (new Bytes (from_hex (sha1.get_string ()))) == 0);

			uint8[] ngm_identity = new ProtobufWriter ()
				.append_bytes (1, new uint8[32])
				.append_varint (2, 15)
				.data;
			uint8[] registration = KtAccountKey.build_registration_data (ngm_identity, 13, 5);
			uint8[] signature = kt.sign_registration_data (registration).get_data ();

			assert_true (signature[0] == 0x30);
			assert_true (signature[2] == 0x04 && signature[3] == 0x14);
			assert_true (new Bytes (signature[4 : 24]).compare (kt.account_key_id ()) == 0);
			assert_true (signature[24] == 0x02 && signature[25] == 0x01 && signature[26] == 0x01);
			assert_true (signature[27] == 0x04);
			int ecdsa_length = signature[28];
			uint8[] ecdsa = signature[29 : 29 + ecdsa_length];

			assert_true (OctagonCrypto.verify (kt.public_spki ().get_data (), registration, ecdsa,
				"SHA256"));
		} catch (GLib.Error e) {
			GLib.error ("device-key-signature failed: %s", e.message);
		}
	}

	private uint8[] from_hex (string hex) {
		var bytes = new uint8[hex.length / 2];
		for (int i = 0; i != bytes.length; i++)
			bytes[i] = (uint8) hex.substring (i * 2, 2).to_long (null, 16);
		return bytes;
	}

	private void decrypts_item_from_tlk () {
		try {
			uint8[] tlk = filled_key (1);
			uint8[] class_key = filled_key (2);
			uint8[] item_key = filled_key (3);
			string tlk_uuid = "AAAAAAAA-0000-0000-0000-000000000001";
			string class_uuid = "BBBBBBBB-0000-0000-0000-000000000002";
			string item_uuid = "CCCCCCCC-0000-0000-0000-000000000003";

			var attributes = new Plist ();
			attributes.set_string ("labl", "KTAccountKey");
			attributes.set_string ("agrp", "ichat");
			uint8[] padded = iso7816_pad (attributes.to_binary ());

			uint8[] nonce = new uint8[16];
			for (int i = 0; i != 16; i++)
				nonce[i] = (uint8) (0xa0 + i);
			var aad = new Bytes[] {
				new Bytes (nonce), new Bytes (item_uuid.data), le8_bytes (2), le8_bytes (0),
				new Bytes (class_uuid.data)
			};
			uint8[] sealed = OctagonCrypto.aes_siv_encrypt (item_key, padded, aad);
			uint8[] data = concat (nonce, sealed);

			var records = new Gee.ArrayList<CloudKitRecord> ();
			records.add (ckks_record (tlk_uuid, "synckey", ckks_string ("class", "tlk")));
			uint8[] class_fields = concat (concat (ckks_string ("class", "classC"),
				ckks_string ("wrappedkey", Base64.encode (
					OctagonCrypto.aes_siv_encrypt (tlk, class_key, new Bytes[] {})))),
				ckks_reference ("parentkeyref", tlk_uuid));
			records.add (ckks_record (class_uuid, "synckey", class_fields));

			uint8[] item_fields = concat (concat (concat (concat (
				ckks_string ("wrappedkey", Base64.encode (
					OctagonCrypto.aes_siv_encrypt (class_key, item_key, new Bytes[] {}))),
				ckks_int ("encver", 2)), ckks_int ("gen", 0)), ckks_bytes ("data", data)),
				ckks_reference ("parentkeyref", class_uuid));
			records.add (ckks_record (item_uuid, "item", item_fields));

			var tlks = new Gee.HashMap<string, Bytes> ();
			tlks[tlk_uuid] = new Bytes (tlk);
			var items = CkksKeychain.decrypt_zone (records, tlks);

			assert_true (items.size == 1);
			assert_true (items[0].attributes.get_string ("labl") == "KTAccountKey");
			assert_true (items[0].attributes.get_string ("agrp") == "ichat");
		} catch (GLib.Error e) {
			GLib.error ("ckks item decrypt failed: %s", e.message);
		}
	}

	private uint8[] filled_key (uint8 seed) {
		var key = new uint8[64];
		for (int i = 0; i != 64; i++)
			key[i] = (uint8) (seed * 40 + i);
		return key;
	}

	private Bytes le8_bytes (int64 value) {
		var bytes = new uint8[8];
		uint64 v = (uint64) value;
		for (int i = 0; i != 8; i++)
			bytes[i] = (uint8) (v >> (8 * i));
		return new Bytes (bytes);
	}

	private uint8[] iso7816_pad (uint8[] data) {
		int total = ((data.length / 16) + 1) * 16;
		var padded = new uint8[total];
		Memory.copy (padded, data, data.length);
		padded[data.length] = 0x80;
		return padded;
	}

	private uint8[] concat (uint8[] a, uint8[] b) {
		var result = new uint8[a.length + b.length];
		Memory.copy (result, a, a.length);
		Memory.copy ((uint8 *) result + a.length, b, b.length);
		return result;
	}

	private CloudKitRecord ckks_record (string name, string type, uint8[] fields) throws Efni.Error {
		uint8[] identifier = new ProtobufWriter ()
			.append_bytes (1, new ProtobufWriter ().append_bytes (1, name.data).data)
			.data;
		uint8[] head = new ProtobufWriter ()
			.append_bytes (2, identifier)
			.append_bytes (3, new ProtobufWriter ().append_bytes (1, type.data).data)
			.data;
		return CloudKitRecord.parse (concat (head, fields));
	}

	private uint8[] ckks_string (string name, string value) {
		return ckks_field (name, new ProtobufWriter ().append_bytes (7, value.data).data);
	}

	private uint8[] ckks_int (string name, int64 value) {
		return ckks_field (name, new ProtobufWriter ().append_varint (4, value).data);
	}

	private uint8[] ckks_bytes (string name, uint8[] value) {
		return ckks_field (name, new ProtobufWriter ().append_bytes (2, value).data);
	}

	private uint8[] ckks_reference (string name, string target) {
		uint8[] record_id = new ProtobufWriter ()
			.append_bytes (1, new ProtobufWriter ().append_bytes (1, target.data).data)
			.data;
		uint8[] reference = new ProtobufWriter ()
			.append_varint (1, 3)
			.append_bytes (2, record_id)
			.data;
		return ckks_field (name, new ProtobufWriter ().append_bytes (9, reference).data);
	}

	private uint8[] ckks_field (string name, uint8[] value) {
		uint8[] identifier = new ProtobufWriter ().append_bytes (1, name.data).data;
		return new ProtobufWriter ()
			.append_bytes (7, new ProtobufWriter ()
				.append_bytes (1, identifier)
				.append_bytes (2, value)
				.data)
			.data;
	}

	private uint8[] signed_info (uint8[] info) {
		return new ProtobufWriter ()
			.append_bytes (1, info)
			.append_bytes (2, { 0x30, 0x44 })
			.data;
	}

	private uint8[] build_ckks_record (string name, string type, string receiver,
			string wrapped_key) {
		uint8[] identifier = new ProtobufWriter ()
			.append_bytes (1, new ProtobufWriter ().append_bytes (1, name.data).data)
			.data;
		return new ProtobufWriter ()
			.append_bytes (2, identifier)
			.append_bytes (3, new ProtobufWriter ().append_bytes (1, type.data).data)
			.append_bytes (7, named_string_field ("receiver", receiver))
			.append_bytes (7, named_string_field ("wrappedkey", wrapped_key))
			.data;
	}

	private uint8[] named_string_field (string name, string value) {
		uint8[] identifier = new ProtobufWriter ().append_bytes (1, name.data).data;
		uint8[] boxed = new ProtobufWriter ().append_bytes (7, value.data).data;
		return new ProtobufWriter ()
			.append_bytes (1, identifier)
			.append_bytes (2, boxed)
			.data;
	}

	private OctagonBottleContents open_sample_bottle (uint8[] open_secret) throws GLib.Error {
		string salt = "A1B2C3D4-E5F6-0718-293A-4B5C6D7E8F90";
		uint8[] bottle, signature_using_escrow, signature_using_peer;
		build_sample_bottle (sample_secret (), salt, out bottle, out signature_using_escrow,
			out signature_using_peer);
		return OctagonBottle.open (bottle, open_secret, salt, signature_using_escrow,
			signature_using_peer);
	}

	private void build_sample_bottle (uint8[] secret, string salt, out uint8[] bottle,
			out uint8[] signature_using_escrow, out uint8[] signature_using_peer) throws GLib.Error {
		var escrow = OctagonEscrowKeys.derive (secret, salt);
		var peer = OctagonEscrowKeys.derive (peer_secret (), salt);

		uint8[] contents = new ProtobufWriter ()
			.append_bytes (3, private_key_message ("peer-signing"))
			.append_bytes (4, private_key_message ("peer-encryption"))
			.data;

		var iv = new uint8[16];
		for (int i = 0; i != iv.length; i++)
			iv[i] = (uint8) (i + 0x40);
		uint8[] tag;
		uint8[] ciphertext = OctagonCrypto.aes_256_gcm_encrypt (escrow.symmetric_key.get_data (),
			iv, contents, out tag);

		uint8[] authenticated = new ProtobufWriter ()
			.append_bytes (1, ciphertext)
			.append_bytes (2, tag)
			.append_bytes (3, iv)
			.data;

		bottle = new ProtobufWriter ()
			.append_bytes (1, "peer-id".data)
			.append_bytes (2, "bottle-id".data)
			.append_bytes (8, escrow.signing_spki.get_data ())
			.append_bytes (9, escrow.encryption_spki.get_data ())
			.append_bytes (10, peer.signing_spki.get_data ())
			.append_bytes (11, peer.encryption_spki.get_data ())
			.append_bytes (12, authenticated)
			.data;

		signature_using_escrow = OctagonCrypto.sign (escrow.signing_key, bottle);
		signature_using_peer = OctagonCrypto.sign (peer.signing_key, bottle);
	}

	private uint8[] private_key_message (string key_data) {
		return new ProtobufWriter ()
			.append_varint (1, OctagonPrivateKey.KEY_TYPE_EC_NIST_CURVES)
			.append_bytes (2, key_data.data)
			.data;
	}

	private uint8[] sample_secret () {
		var secret = new uint8[72];
		for (int i = 0; i != secret.length; i++)
			secret[i] = (uint8) (i * 5 + 3);
		return secret;
	}

	private uint8[] peer_secret () {
		var secret = new uint8[72];
		for (int i = 0; i != secret.length; i++)
			secret[i] = (uint8) (i * 11 + 9);
		return secret;
	}
}
