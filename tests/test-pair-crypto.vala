using Efni;

namespace Idun.PairCryptoTest {
	public void add_tests () {
		GLib.Test.add_func ("/PairCrypto/round-trips-between-peers", round_trips_between_peers);
		GLib.Test.add_func ("/PairCrypto/rejects-tampered-payload", rejects_tampered_payload);
	}

	private void round_trips_between_peers () {
		var alice = new PairCrypto (MessageIdentity.generate ());
		var bob = new PairCrypto (MessageIdentity.generate ());
		var message = new Bytes ({ 0x10, 0x09, 0x2a, 0x24, 0x54, 0x45, 0x53, 0x54, 0x78, 0xff });

		try {
			Bytes payload = alice.encrypt (bob.identity.public_key, message.get_data ());
			uint8[] opened = bob.decrypt (alice.identity.public_key, payload);
			assert_true (new Bytes (opened).compare (message) == 0);
		} catch (Efni.Error e) {
			printerr ("%s\n", e.message);
			assert_not_reached ();
		}
	}

	private void rejects_tampered_payload () {
		var alice = new PairCrypto (MessageIdentity.generate ());
		var bob = new PairCrypto (MessageIdentity.generate ());

		try {
			Bytes payload = alice.encrypt (bob.identity.public_key, { 0x01, 0x02, 0x03, 0x04 });
			uint8[] tampered = payload.get_data ();
			tampered[tampered.length - 1] ^= 0xff;

			bob.decrypt (alice.identity.public_key, new Bytes (tampered));
			assert_not_reached ();
		} catch (Efni.Error e) {
		}
	}
}
