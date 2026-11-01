using Idun;
namespace Idun.Examples {
	int main (string[] args) {
		try {
			string session_id = "19859D50-DFA5-471A-A281-876E77E46EE1";
			var signing_key = TetraCrypto.generate_key_agreement_key ();
			var prekey = TetraCrypto.generate_key_agreement_key ();
			var prekey_material = FaceTimeQuickRelay.build_prekey_material (session_id, signing_key,
				TetraCrypto.public_key_point (prekey));

			var skm = new uint8[32];
			var sks = new uint8[16];
			var ski = new uint8[16];
			OpenSSL.Rng.generate (skm);
			OpenSSL.Rng.generate (sks);
			OpenSSL.Rng.generate (ski);
			uint8[] avc_data = FaceTimeEndpoint.build_avc_container ("2CC7DA48-8AA7-41EA-9662-3F0027EFEC63",
				0x12345678, 17188950392802533376U, 457613262);
			var avcblob_material = FaceTimeQuickRelay.build_avcblob_material (session_id, skm, sks, ski, avc_data);

			uint8[] avc = { 0x00, 0xab, 0x1d, 0x85 };
			uint8[] ids = { 0x10, 0xe1, 0x75, 0x05 };
			uint8[] body = FaceTimeRelayProtocol.build_allocbind (avc, ids,
				new FaceTimeMaterial[] { prekey_material, avcblob_material });
			var sb = new StringBuilder ();
			foreach (uint8 b in body)
				sb.append_printf ("%02x", b);
			print ("%s\n", sb.str);
		} catch (GLib.Error e) {
			printerr ("error: %s\n", e.message);
			return 1;
		}
		return 0;
	}
}
