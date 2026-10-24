using Efni;

namespace Idun.PairCryptoTest {
	public void add_tests () {
		GLib.Test.add_func ("/PairCrypto/round-trips-between-peers", round_trips_between_peers);
		GLib.Test.add_func ("/PairCrypto/verifies-the-sender-signature", verifies_the_sender_signature);
		GLib.Test.add_func ("/PairCrypto/rejects-a-forged-signature", rejects_a_forged_signature);
	}

	private void round_trips_between_peers () {
		var alice = new PairCrypto (MessageIdentity.generate ());
		var bob = new PairCrypto (MessageIdentity.generate ());
		var message = new Bytes ({ 0x10, 0x09, 0x2a, 0x24, 0x54, 0x45, 0x53, 0x54, 0x78, 0xff });

		try {
			Bytes payload = alice.encrypt (bob.identity.public_key, message.get_data ());
			uint8[] opened = bob.decrypt (payload);
			assert_true (new Bytes (opened).compare (message) == 0);
		} catch (Efni.Error e) {
			printerr ("%s\n", e.message);
			assert_not_reached ();
		}
	}

	private void verifies_the_sender_signature () {
		var alice = new PairCrypto (MessageIdentity.generate ());
		var bob = new PairCrypto (MessageIdentity.generate ());

		try {
			Bytes payload = alice.encrypt (bob.identity.public_key, { 0x01, 0x02, 0x03, 0x04 });
			assert_true (bob.verify (alice.identity.public_key, payload));
		} catch (Efni.Error e) {
			printerr ("%s\n", e.message);
			assert_not_reached ();
		}
	}

	private void rejects_a_forged_signature () {
		var alice = new PairCrypto (MessageIdentity.generate ());
		var bob = new PairCrypto (MessageIdentity.generate ());

		try {
			Bytes payload = alice.encrypt (bob.identity.public_key, { 0x01, 0x02, 0x03, 0x04 });
			uint8[] forged = payload.get_data ();
			forged[forged.length - 1] ^= 0xff;
			assert_false (bob.verify (alice.identity.public_key, new Bytes (forged)));
		} catch (Efni.Error e) {
			printerr ("%s\n", e.message);
			assert_not_reached ();
		}
	}
}
