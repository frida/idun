using Efni;

namespace Idun.TetraSessionTest {
	public void add_tests () {
		GLib.Test.add_func ("/TetraSession/establishes-and-exchanges", establishes_and_exchanges);
	}

	private void establishes_and_exchanges () {
		var alice_signing = TetraCrypto.generate_key_agreement_key ();
		uint8[] alice_signing_point = TetraCrypto.compact_point (TetraCrypto.public_key_point (alice_signing));

		Bytes bob_prekey = TetraCrypto.generate_key_agreement_key ();
		uint8[] bob_prekey_point = TetraCrypto.compact_point (TetraCrypto.public_key_point (bob_prekey));
		var bob_kyber_public = new uint8[Kyber.PUBLIC_KEY_BYTES];
		var bob_kyber_secret = new uint8[Kyber.SECRET_KEY_BYTES];
		Kyber.keypair (bob_kyber_public, bob_kyber_secret);

		var alice = TetraSession.establish_as_sender (alice_signing, bob_prekey_point, bob_kyber_public);
		uint8[] message = alice.seal ("across the ratchet".data, { 7, 7, 7 });

		var parsed = TetraMessage.parse (message);
		var bob = TetraSession.establish_as_receiver (new Bytes (ALICE_KEY.data), bob_prekey,
			bob_kyber_secret, parsed.ecdh_public_key.get_data (), parsed.kem_encapsulation.get_data ());

		uint8[] plaintext = bob.open (message, alice_signing_point, { 7, 7, 7 });
		assert_true (new Bytes (plaintext).compare (new Bytes ("across the ratchet".data)) == 0);
	}

	private const string ALICE_KEY =
		"-----BEGIN PRIVATE KEY-----\n" +
		"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4reMHFY5YGZ1zGJK\n" +
		"QO2LdzMlylho9Kyv4qExN6vRK82hRANCAASJLmUCAcaK0A2KidzkIrjAijWty4iW\n" +
		"LEyPIwpbHLC1IbdN4lL5F4bbd+9PbJoVtRSR5q74ljf6o9nFPyfLrcVn\n" +
		"-----END PRIVATE KEY-----\n";
}
