using Efni;

namespace Idun.TetraSessionTest {
	public void add_tests () {
		GLib.Test.add_func ("/TetraSession/holds-a-conversation", holds_a_conversation);
		GLib.Test.add_func ("/TetraSession/survives-serialization", survives_serialization);
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

		var context = make_context (alice_point, bob_point, bob_kyber_public);
		var alice = TetraSession.establish_as_sender (alice_signing, context, bob_prekey_point,
			bob_kyber_public);
		uint8[] m0 = alice.seal ("hi bob".data, { 1 });

		var parsed = TetraMessage.parse (m0);
		var bob = TetraSession.establish_as_receiver (bob_signing, context, bob_prekey, bob_kyber_secret,
			parsed.ecdh_public_key.get_data (), parsed.kem_encapsulation.get_data ());
		assert_opens (bob, m0, alice_point, { 1 }, "hi bob");

		uint8[] r0 = bob.seal ("hi alice".data, { 2 });
		assert_opens (alice, r0, bob_point, { 2 }, "hi alice");

		uint8[] m1 = alice.seal ("again".data, { 3 });
		assert_opens (bob, m1, alice_point, { 3 }, "again");
	}

	private void survives_serialization () {
		Bytes bob_prekey = TetraCrypto.generate_key_agreement_key ();
		uint8[] bob_prekey_point = TetraCrypto.compact_point (TetraCrypto.public_key_point (bob_prekey));
		var bob_kyber_public = new uint8[Kyber.PUBLIC_KEY_BYTES];
		var bob_kyber_secret = new uint8[Kyber.SECRET_KEY_BYTES];
		Kyber.keypair (bob_kyber_public, bob_kyber_secret);

		Bytes alice_signing = TetraCrypto.generate_key_agreement_key ();
		uint8[] alice_point = TetraCrypto.compact_point (TetraCrypto.public_key_point (alice_signing));
		Bytes bob_signing = TetraCrypto.generate_key_agreement_key ();
		uint8[] bob_point = TetraCrypto.compact_point (TetraCrypto.public_key_point (bob_signing));

		var context = make_context (alice_point, bob_point, bob_kyber_public);
		var alice = TetraSession.establish_as_sender (alice_signing, context, bob_prekey_point,
			bob_kyber_public);
		uint8[] m0 = alice.seal ("one".data, { 1 });

		var parsed = TetraMessage.parse (m0);
		var bob = TetraSession.establish_as_receiver (bob_signing, context, bob_prekey, bob_kyber_secret,
			parsed.ecdh_public_key.get_data (), parsed.kem_encapsulation.get_data ());

		var alice2 = TetraSession.restore (alice.serialize ());
		var bob2 = TetraSession.restore (bob.serialize ());

		assert_opens (bob2, m0, alice_point, { 1 }, "one");
		uint8[] reply = bob2.seal ("two".data, { 2 });
		assert_opens (alice2, reply, bob_point, { 2 }, "two");
	}

	private TetraRootContext make_context (uint8[] initiator_signing, uint8[] responder_signing,
			uint8[] responder_kyber_public) {
		return new TetraRootContext (
			new Bytes ("tel:+10000000000".data),
			new Bytes (new uint8[32]),
			new Bytes (initiator_signing),
			new Bytes ("mailto:bob@example.com".data),
			new Bytes (new uint8[32]),
			new Bytes (responder_signing),
			new Bytes (responder_kyber_public));
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
