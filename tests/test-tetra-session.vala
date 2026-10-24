using Efni;

namespace Idun.TetraSessionTest {
	public void add_tests () {
		GLib.Test.add_func ("/TetraSession/holds-a-conversation", holds_a_conversation);
	}

	private void holds_a_conversation () {
		Bytes bob_prekey = TetraCrypto.generate_key_agreement_key ();
		uint8[] bob_prekey_point = TetraCrypto.compact_point (TetraCrypto.public_key_point (bob_prekey));
		var bob_kyber_public = new uint8[Kyber.PUBLIC_KEY_BYTES];
		var bob_kyber_secret = new uint8[Kyber.SECRET_KEY_BYTES];
		Kyber.keypair (bob_kyber_public, bob_kyber_secret);

		Bytes alice_signing = TetraCrypto.generate_key_agreement_key ();
		uint8[] alice_point = TetraCrypto.compact_point (TetraCrypto.public_key_point (alice_signing));
		Bytes bob_signing = TetraCrypto.generate_key_agreement_key ();
		uint8[] bob_point = TetraCrypto.compact_point (TetraCrypto.public_key_point (bob_signing));

		var alice = TetraSession.establish_as_sender (alice_signing, bob_prekey_point, bob_kyber_public);
		uint8[] m0 = alice.seal ("hi bob".data, { 1 });

		var parsed = TetraMessage.parse (m0);
		var bob = TetraSession.establish_as_receiver (bob_signing, bob_prekey, bob_kyber_secret,
			parsed.ecdh_public_key.get_data (), parsed.kem_encapsulation.get_data ());
		assert_opens (bob, m0, alice_point, { 1 }, "hi bob");

		uint8[] r0 = bob.seal ("hi alice".data, { 2 });
		assert_opens (alice, r0, bob_point, { 2 }, "hi alice");

		uint8[] m1 = alice.seal ("again".data, { 3 });
		assert_opens (bob, m1, alice_point, { 3 }, "again");
	}

	private void assert_opens (TetraSession session, uint8[] message, uint8[] signing_point,
			uint8[] authenticated_data, string expected) {
		try {
			uint8[] opened = session.open (message, signing_point, authenticated_data);
			assert_true (new Bytes (opened).compare (new Bytes (expected.data)) == 0);
		} catch (Efni.Error e) {
			assert_not_reached ();
		}
	}
}
