using Efni;

namespace Idun.OctagonEscrowKeysTest {
	public void add_tests () {
		GLib.Test.add_func ("/OctagonEscrowKeys/derives-deterministically", derives_deterministically);
	}

	private void derives_deterministically () {
		var secret = new uint8[72];
		for (int i = 0; i != secret.length; i++)
			secret[i] = (uint8) (i * 7 + 1);
		string salt = "9C8E7F6A-0B1C-2D3E-4F50-6172839AB0C1";

		try {
			var first = OctagonEscrowKeys.derive (secret, salt);
			var second = OctagonEscrowKeys.derive (secret, salt);

			assert_true (first.symmetric_key.length == 32);
			assert_true (first.signing_spki.length == 120);
			assert_true (first.encryption_spki.length == 120);

			assert_true (first.symmetric_key.compare (second.symmetric_key) == 0);
			assert_true (first.signing_spki.compare (second.signing_spki) == 0);
			assert_true (first.encryption_spki.compare (second.encryption_spki) == 0);
			assert_true (first.signing_key.compare (second.signing_key) == 0);
			assert_true (first.signing_spki.compare (first.encryption_spki) != 0);
		} catch (GLib.Error e) {
			GLib.error ("derive failed: %s", e.message);
		}
	}
}
