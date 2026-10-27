using Efni;

namespace Idun.FaceTimeMediaTest {
	public void add_tests () {
		GLib.Test.add_func ("/FaceTimeMedia/unwraps-known-answer", unwraps_known_answer);
		GLib.Test.add_func ("/FaceTimeMedia/wraps-and-unwraps-roundtrip", wraps_and_unwraps_roundtrip);
	}

	private void unwraps_known_answer () {
		try {
			uint8[] material = FaceTimeMediaCrypto.unwrap_key_material (new Bytes (KEY_PEM.data),
				decode_hex (SEALED));
			assert_true (new Bytes (material).compare (new Bytes (decode_hex (MATERIAL))) == 0);
		} catch (Efni.Error e) {
			assert_not_reached ();
		}
	}

	private void wraps_and_unwraps_roundtrip () {
		try {
			var key = TetraCrypto.generate_key_agreement_key ();
			uint8[] point = TetraCrypto.public_key_point (key);
			uint8[] material = decode_hex (MATERIAL);

			uint8[] sealed = FaceTimeMediaCrypto.wrap_key_material (point, material);
			assert_true (sealed.length == 65 + material.length + 8);

			uint8[] opened = FaceTimeMediaCrypto.unwrap_key_material (key, sealed);
			assert_true (new Bytes (opened).compare (new Bytes (material)) == 0);
		} catch (Efni.Error e) {
			assert_not_reached ();
		}
	}

	private const string MATERIAL = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
	private const string SEALED = "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794961e4ce4e740931e1b4a401e856c03fb68f91717bbecca2d9113ba22908d952ccf0891d63e4a7ae7";
	private const string KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgO14s9f3IhSF1XObu\n0Y9dR7YJeyveNYoK5o+MRsNzUmyhRANCAAQGqhFB+IgxMaOpVyoLWL0RIc7QFGST\nUcOSEK/G9si1xRKQ20atNEaElSLSRTAs2j9shDHEHXIiIYENleX7v0Ku\n-----END PRIVATE KEY-----\n";

	private uint8[] decode_hex (string hex) {
		var bytes = new uint8[hex.length / 2];
		for (int i = 0; i != bytes.length; i++)
			bytes[i] = (uint8) (hex.substring (i * 2, 2).to_long (null, 16));
		return bytes;
	}
}
