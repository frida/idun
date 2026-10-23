using Efni;

namespace Idun.MessageIdentityTest {
	public void add_tests () {
		GLib.Test.add_func ("/MessageIdentity/reconstructs-from-keys", reconstructs_from_keys);
	}

	private void reconstructs_from_keys () {
		var original = MessageIdentity.generate ();
		var restored = MessageIdentity.from_keys (original.encryption_key, original.signing_key);

		assert_true (restored.public_key.compare (original.public_key) == 0);
	}
}
