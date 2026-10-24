using Efni;

namespace Idun.TetraMessageTest {
	public void add_tests () {
		GLib.Test.add_func ("/TetraMessage/round-trips", round_trips);
		GLib.Test.add_func ("/TetraMessage/reparses-captured-wire-bytes", reparses_captured_wire_bytes);
	}

	private void round_trips () {
		var original = new TetraMessage (15, new Bytes ({ 1, 2, 3, 4 }), new Bytes (new uint8[64]),
			new Bytes (new uint8[32]), 7, new Bytes (new uint8[16]), new Bytes ({ 9, 9 }),
			new Bytes ({ 5 }));

		var restored = TetraMessage.parse (original.serialize ());

		assert_true (restored.version == 15);
		assert_true (restored.message_index == 7);
		assert_true (restored.ciphertext.compare (original.ciphertext) == 0);
		assert_true (restored.kem_encapsulation.compare (original.kem_encapsulation) == 0);
		assert_true (restored.used_registered_keys.compare (original.used_registered_keys) == 0);
	}

	private void reparses_captured_wire_bytes () {
		uint8[] wire = decode_hex (CAPTURED_RATCHET_MESSAGE);

		var message = TetraMessage.parse (wire);

		assert_true (message.version == 15);
		assert_true (message.ciphertext.length == 256);
		assert_true (message.signature.length == 64);
		assert_true (message.ecdh_public_key.length == 32);
		assert_true (message.message_key_indicator.length == 16);
		assert_true (message.kem_encapsulation == null);
		assert_true (new Bytes (message.serialize ()).compare (new Bytes (wire)) == 0);
	}

	private const string CAPTURED_RATCHET_MESSAGE =
		"080f1280028d87883f1cc8bfaf2b545cd45b7e319c0859a523c1fc548fc0f86f0363b9ec656fe87e" +
		"56505b2d97e8a81a0d6a0f48613aee435c22b1e94542181d6593caaa32720966edb8d1f5f5db1f67" +
		"cf1e074fd481c83b3f760a9269c05e0a63c884332d9fa7bd35395c79f97d680f1cc32ba174ee1196" +
		"b4b622d746ba8182aa0f6c9f5417de5619d0b8d9bbb5196f81dbc0ef7fb774deb822dadb0945cb76" +
		"60dccf8f3cba6333c62543255f0f07a29054512f82eb7aeae3c99437645d44db4cc270548cecccf5" +
		"dd7b2977c430889a5f0ac4e0b3002805aec49708f86549ecd6dc5bb523b4c6b577fbce8703e838cc" +
		"fbc8ed88c1f646316d94a1b78d63bf76f41c7127461a404da7194f44902248709e6312961122b0dd" +
		"4723e6a78d6e39f8e5b77f415d2b1f8b9f7b9ec9def76ef0afa325f700c4f7ff705bde00d522a38e" +
		"9a84414bdd9071222003e1647462c1c89fb51fd9db40032643f1c8e89815054d5c9b763d74b90e4d" +
		"2638004a10be0e2cd1ae568d738a4f31ad2f7df1a4";

	private uint8[] decode_hex (string hex) {
		var bytes = new uint8[hex.length / 2];
		for (int i = 0; i != bytes.length; i++)
			bytes[i] = (uint8) (hex.substring (i * 2, 2).to_long (null, 16));
		return bytes;
	}
}
