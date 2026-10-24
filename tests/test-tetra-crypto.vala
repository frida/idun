using Efni;

namespace Idun.TetraCryptoTest {
	public void add_tests () {
		GLib.Test.add_func ("/TetraCrypto/inner-message-round-trips", inner_message_round_trips);
		GLib.Test.add_func ("/TetraCrypto/aes-256-ctr-matches-nist", aes_256_ctr_matches_nist);
		GLib.Test.add_func ("/TetraCrypto/hkdf-matches-rfc5869", hkdf_matches_rfc5869);
		GLib.Test.add_func ("/TetraCrypto/i2osp-is-big-endian", i2osp_is_big_endian);
		GLib.Test.add_func ("/TetraCrypto/root-ratchet-splits-output", root_ratchet_splits_output);
	}

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
