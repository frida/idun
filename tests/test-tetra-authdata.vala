using Efni;

namespace Idun.TetraAuthDataTest {
	public void add_tests () {
		GLib.Test.add_func ("/TetraAuthData/reproduces-captured-blob", reproduces_captured_blob);
	}

	private void reproduces_captured_blob () {
		TetraBinding[] bindings = {
			new TetraBinding (new Bytes ("tel:+4748270645".data), new Bytes (decode_hex ("f946664dfd8c7ea0ed58d9062321142231d266f86b458e89ae8e30d69bfaf16e")),
				new Bytes (decode_hex ("dbf5d35caf5250f23c47337693eea96d4dd827a9a868b6e2271147cd859ea2e9"))),
			new TetraBinding (new Bytes ("tel:+4748270645".data), new Bytes (decode_hex ("b4cf12e3f001248a438e824fa4c2c30121915dbbbaaf69e50d4ac2755cc0fa3a")),
				new Bytes (decode_hex ("66ce2c2b1d82e6c922071f25c751be5088b286786b6661d319d855b5dffea9ee")))
		};

		uint8[] built = TetraCrypto.build_authenticated_data ("com.apple.private.alloy.facetime.multi".data,
			decode_hex ("c999fd908f4cda286955c1bfda83ae43"), decode_hex ("5012aec942aae0c11cb6a0d6d675da76f240fdd982f7a34d35e45d47bc6b613e"), bindings);

		assert_true (new Bytes (built).compare (new Bytes (decode_hex (CAPTURED))) == 0);
	}

	private const string CAPTURED = "00000026636f6d2e6170706c652e707269766174652e616c6c6f792e6661636574696d652e6d756c7469c999fd908f4cda286955c1bfda83ae435012aec942aae0c11cb6a0d6d675da76f240fdd982f7a34d35e45d47bc6b613e010000000000000f74656c3a2b3437343832373036343500000020f946664dfd8c7ea0ed58d9062321142231d266f86b458e89ae8e30d69bfaf16edbf5d35caf5250f23c47337693eea96d4dd827a9a868b6e2271147cd859ea2e90000000f74656c3a2b3437343832373036343500000020b4cf12e3f001248a438e824fa4c2c30121915dbbbaaf69e50d4ac2755cc0fa3a66ce2c2b1d82e6c922071f25c751be5088b286786b6661d319d855b5dffea9ee00000000000000000000";

	private uint8[] decode_hex (string hex) {
		var bytes = new uint8[hex.length / 2];
		for (int i = 0; i != bytes.length; i++)
			bytes[i] = (uint8) (hex.substring (i * 2, 2).to_long (null, 16));
		return bytes;
	}
}
