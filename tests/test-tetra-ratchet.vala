using Efni;

namespace Idun.TetraRatchetTest {
	public void add_tests () {
		GLib.Test.add_func ("/TetraRatchet/sender-and-receiver-agree", sender_and_receiver_agree);
		GLib.Test.add_func ("/TetraRatchet/seals-through-the-ratchet", seals_through_the_ratchet);
	}

	private void sender_and_receiver_agree () {
		uint8[] chain = new uint8[32];
		for (int i = 0; i != 32; i++)
			chain[i] = (uint8) (i + 1);

		var sender = new TetraSymmetricRatchet (chain);
		var receiver = new TetraSymmetricRatchet (chain);

		uint64 index;
		uint8[] first = sender.advance (out index);
		sender.advance (out index);
		uint8[] third = sender.advance (out index);

		assert_true (new Bytes (receiver.message_key_for (0)).compare (new Bytes (first)) == 0);
		assert_true (new Bytes (receiver.message_key_for (2)).compare (new Bytes (third)) == 0);
	}

	private void seals_through_the_ratchet () {
		uint8[] chain = new uint8[32];
		var sender = new TetraSymmetricRatchet (chain);
		var receiver = new TetraSymmetricRatchet (chain);
		var signing_key = new Bytes (TEST_KEY.data);
		uint8[] plaintext = "ratcheted".data;

		uint64 index;
		uint8[] message_key = sender.advance (out index);
		uint8[] sealed = TetraCrypto.seal_message (message_key, signing_key, new uint8[32], index,
			plaintext, { 1, 2, 3 });

		uint8[] opened = TetraCrypto.open_message (receiver.message_key_for (index), signing_key,
			sealed, { 1, 2, 3 });
		assert_true (new Bytes (opened).compare (new Bytes (plaintext)) == 0);
	}

	private const string TEST_KEY =
		"-----BEGIN PRIVATE KEY-----\n" +
		"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4reMHFY5YGZ1zGJK\n" +
		"QO2LdzMlylho9Kyv4qExN6vRK82hRANCAASJLmUCAcaK0A2KidzkIrjAijWty4iW\n" +
		"LEyPIwpbHLC1IbdN4lL5F4bbd+9PbJoVtRSR5q74ljf6o9nFPyfLrcVn\n" +
		"-----END PRIVATE KEY-----\n";
}
