using Efni;

namespace Idun.TetraCryptoTest {
	public void add_tests () {
		GLib.Test.add_func ("/TetraCrypto/inner-message-round-trips", inner_message_round_trips);
		GLib.Test.add_func ("/TetraCrypto/aes-256-ctr-matches-nist", aes_256_ctr_matches_nist);
		GLib.Test.add_func ("/TetraCrypto/hkdf-matches-rfc5869", hkdf_matches_rfc5869);
		GLib.Test.add_func ("/TetraCrypto/i2osp-is-big-endian", i2osp_is_big_endian);
		GLib.Test.add_func ("/TetraCrypto/root-ratchet-splits-output", root_ratchet_splits_output);
		GLib.Test.add_func ("/TetraCrypto/ecdsa-signs-and-verifies", ecdsa_signs_and_verifies);
		GLib.Test.add_func ("/TetraCrypto/builds-signature-transcript", builds_signature_transcript);
		GLib.Test.add_func ("/TetraCrypto/derives-message-key-indicator", derives_message_key_indicator);
	}

	private void ecdsa_signs_and_verifies () {
		var key = new Bytes (TEST_P256_KEY.data);
		uint8[] data = { 1, 2, 3, 4, 5 };

		uint8[] signature = TetraCrypto.sign (key, data);

		assert_true (signature.length == 64);
		assert_true (TetraCrypto.verify (key, data, signature));
		assert_false (TetraCrypto.verify (key, { 1, 2, 3, 4, 6 }, signature));
	}

	private void derives_message_key_indicator () {
		uint8[] indicator = TetraCrypto.derive_message_key_indicator (new uint8[32]);
		uint8[] again = TetraCrypto.derive_message_key_indicator (new uint8[32]);

		assert_true (indicator.length == 16);
		assert_true (new Bytes (indicator).compare (new Bytes (again)) == 0);
	}

	private void builds_signature_transcript () {
		uint8[] captured = decode_hex (CAPTURED_TRANSCRIPT);
		uint8[] ciphertext = captured[40 : 296];
		uint8[] authenticated_data = captured[296 : captured.length];

		uint8[] built = TetraCrypto.build_signature_transcript (true, 15, ciphertext, authenticated_data);

		assert_true (new Bytes (built).compare (new Bytes (captured)) == 0);
	}

	private const string CAPTURED_TRANSCRIPT =
		"636f6d2e6170706c652e54657472612e4d6573736167655369676e61747572650000000f000001003dd95fae4dcca50d" +
		"4ccb206e022ef32fe901b9796b4728bed6374e846c90d5e9c2762a7ba10e7dd714ea559cc851934b31b40b64e2fcc6b8" +
		"e7c2ee13d0426414929b8c937ee878ac63990acd5a4e741adf92af7a4758fdbd13436d8f12eb40fe869b07b377a5e2e5" +
		"c4b76c646b584d7915d29305e7d45aefc6462fa61f205ed27a1845149d1ba2416fb4fa38f397193a50a58a3824bacd96" +
		"daf59a69d7a5463ea3d2cb92de82e306c7cbc2d62abcd6c6c6038e377a2f5dda7f6915d4a20c0fdcaff08d7738343fd6" +
		"af7aa810d655c24ca35cf2ecb5398325368bd85def2c6744d43b021ffbbac0ddccf0a1c4effd37acb80095b15a00dba3" +
		"edf7f46b7d18dad300000026636f6d2e6170706c652e707269766174652e616c6c6f792e6661636574696d652e6d756c" +
		"7469c999fd908f4cda286955c1bfda83ae435012aec942aae0c11cb6a0d6d675da76f240fdd982f7a34d35e45d47bc6b" +
		"613e010000000000000f74656c3a2b3437343832373036343500000020f946664dfd8c7ea0ed58d9062321142231d266" +
		"f86b458e89ae8e30d69bfaf16edbf5d35caf5250f23c47337693eea96d4dd827a9a868b6e2271147cd859ea2e9000000" +
		"0f74656c3a2b3437343832373036343500000020b4cf12e3f001248a438e824fa4c2c30121915dbbbaaf69e50d4ac275" +
		"5cc0fa3a66ce2c2b1d82e6c922071f25c751be5088b286786b6661d319d855b5dffea9ee00000000000000000000";

	private const string TEST_P256_KEY =
		"-----BEGIN PRIVATE KEY-----\n" +
		"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4reMHFY5YGZ1zGJK\n" +
		"QO2LdzMlylho9Kyv4qExN6vRK82hRANCAASJLmUCAcaK0A2KidzkIrjAijWty4iW\n" +
		"LEyPIwpbHLC1IbdN4lL5F4bbd+9PbJoVtRSR5q74ljf6o9nFPyfLrcVn\n" +
		"-----END PRIVATE KEY-----\n";

	private void i2osp_is_big_endian () {
		assert_true (new Bytes (TetraCrypto.i2osp (256, 4)).compare (new Bytes (decode_hex ("00000100"))) == 0);
		assert_true (new Bytes (TetraCrypto.i2osp (15, 4)).compare (new Bytes (decode_hex ("0000000f"))) == 0);
		assert_true (new Bytes (TetraCrypto.i2osp (32, 2)).compare (new Bytes (decode_hex ("0020"))) == 0);
	}

	private void root_ratchet_splits_output () {
		uint8[] root, chain;
		TetraCrypto.derive_root_and_chain (new uint8[32], new uint8[32], null, "TetraRatchet-".data,
			out root, out chain);

		assert_true (root.length == 32);
		assert_true (chain.length == 32);
		assert_true (new Bytes (root).compare (new Bytes (chain)) != 0);
	}

	private void inner_message_round_trips () {
		var original = new TetraInnerMessage (new Bytes ({ 1, 2, 3 }), new Bytes ({ 4, 5 }));

		var restored = TetraInnerMessage.parse (original.serialize ());

		assert_true (restored.plaintext.compare (original.plaintext) == 0);
		assert_true (restored.kt_gossip_data.compare (original.kt_gossip_data) == 0);
	}

	private void aes_256_ctr_matches_nist () {
		uint8[] key = decode_hex ("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
		uint8[] iv = decode_hex ("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
		uint8[] plaintext = decode_hex ("6bc1bee22e409f96e93d7e117393172a");

		uint8[] ciphertext = TetraCrypto.aes_256_ctr (key, iv, plaintext);

		assert_true (new Bytes (ciphertext).compare (
			new Bytes (decode_hex ("601ec313775789a5b7a7f504bbf3d228"))) == 0);
		assert_true (new Bytes (TetraCrypto.aes_256_ctr (key, iv, ciphertext)).compare (
			new Bytes (plaintext)) == 0);
	}

	private void hkdf_matches_rfc5869 () {
		uint8[] okm = decode_hex (
			"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
		uint8[] info = decode_hex ("f0f1f2f3f4f5f6f7f8f9");

		uint8[] full = TetraCrypto.hkdf_extract_and_expand (OpenSSL.ShortName.sha256,
			decode_hex ("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
			decode_hex ("000102030405060708090a0b0c"), info, 42);
		assert_true (new Bytes (full).compare (new Bytes (okm)) == 0);

		uint8[] from_prk = TetraCrypto.hkdf_expand (OpenSSL.ShortName.sha256,
			decode_hex ("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
			info, 42);
		assert_true (new Bytes (from_prk).compare (new Bytes (okm)) == 0);
	}

	private uint8[] decode_hex (string hex) {
		var bytes = new uint8[hex.length / 2];
		for (int i = 0; i != bytes.length; i++)
			bytes[i] = (uint8) (hex.substring (i * 2, 2).to_long (null, 16));
		return bytes;
	}
}
