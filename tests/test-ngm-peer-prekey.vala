using Efni;

namespace Idun.NgmPeerPrekeyTest {
	public void add_tests () {
		GLib.Test.add_func ("/NgmPeerPrekey/parses-a-published-prekey", parses_a_published_prekey);
		GLib.Test.add_func ("/NgmPeerPrekey/round-trips-our-own-identity", round_trips_our_own_identity);
	}

	private void parses_a_published_prekey () {
		var prekey = NgmPeerPrekey.parse (new Bytes (decode_hex (PREKEY)),
			new Bytes (decode_hex (KT_LOGGABLE)));

		assert_true (new Bytes (prekey.ecdh_point.get_data ()).compare (new Bytes (decode_hex (
			"a3706c7d6e797c2ad78b6007c0942327660bcba3b7b50eb7adf543c2afabe39c"))) == 0);
		assert_true (prekey.kyber_public.length == 1568);
		assert_true (new Bytes (prekey.signing_point.get_data ()).compare (new Bytes (decode_hex (
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))) == 0);
	}

	private void round_trips_our_own_identity () {
		try {
			var identity = NgmIdentity.generate ();
			var prekey = NgmPeerPrekey.parse (new Bytes (identity.device_prekey_data (1792659144.3, 15)),
				new Bytes (identity.kt_loggable_data (15, 13, 5)));

			assert_true (new Bytes (prekey.ecdh_point.get_data ()).compare (
				new Bytes (identity.prekey_compact_key ())) == 0);
			assert_true (new Bytes (prekey.kyber_public.get_data ()).compare (
				new Bytes (identity.kem_public_key ())) == 0);
			assert_true (new Bytes (prekey.signing_point.get_data ()).compare (
				new Bytes (identity.signing_compact_key ())) == 0);
		} catch (Efni.Error e) {
			assert_not_reached ();
		}
	}

	private const string KT_LOGGABLE =
		"0a220a20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

	private const string PREKEY =
		"0a20a3706c7d6e797c2ad78b6007c0942327660bcba3b7b50eb7adf543c2afabe39c1240ee17e64f956bccb4dfe07b8d" +
		"3ba4863ce44e46d049948e5a24a02208175e5e4aac18b57a0f522d102cdd6a5f3d737b4ad4313490a68a07c3db3fe023" +
		"c1f3e25e19f63f14b273b6da4122e50c0aa00c2242ce912c32cb4ba197353fe334c52d21b3c9d048952924adba650fc5" +
		"8c41444ad9691fb60b4d1ef902e28440e59619beca4666950150969ceb8066e1727d4076764838a7c88b4d25e62256b0" +
		"c24faa0a098a4318722fe5653f2f60c35ab588686670d03b6a229bacc4827843230177612090868bd99c13015bc45b69" +
		"8edbaa27d4999797937b074b619a4a3d2da864fa991f68352bff699ef52291bf089588d51bdb6356158cbdd70399d8ca" +
		"ca9aa46092e64d21da849e864ebb045eb388117250524e817f5af19814b22012bb02029b026b08083e2389e2e02ea4a4" +
		"666e26b61f1a7dde720bf7378de93753badc64fbc53af0686c1ec13ad2c5cde5d60e65f4219e22b30907a45f3b6580f5" +
		"a5e25693c649cc5f19b037b5b57e1142ea70ca22196d879c6c963012a681bde86a9476f2264148b10488bda08b9a3ea3" +
		"afbc9829c3b448c06331d8d0ceebeb2ab018a68c819cb37c12feb865996bb6f8f551478ba9c1ab2f887c6ea57339d94a" +
		"7670d748243b3d6aca3004733b9b54c0bf38b66fb74cac571685dc5fabf733dd012240581326463e0b795fea25126353" +
		"672a1a450de75164c094b68a9af3ec363471887913aa770b197ae01019928afbb5396a05cf27a356353caac288a80e30" +
		"4626567e086ab787d26f3226b3e4db7e1a5a01119a3872353be98a2e55fb06801817045a756839b8c502c821f9a1a244" +
		"7c70f01d1a401870f86f8c7682629094e8ca690559464818c92280865e343c0ebc9caab09a4c30925106768db956b0d6" +
		"41cb26c9f27b59f7f5a4a830c90d36066c6ac86526608df342c6d0bcabc58c23d2ae39796f9c8a6d13063361e249c029" +
		"c7d457629519072c84690af99d9c60b345b533891c3e1e2bc66d268ff3106e7a6468a20b6dabfc33142271b01610d1e4" +
		"5238e1037f3b7e1e4904aaa66594f3bf59541d031b35e948c7d402adac4730bf2b432ec257dc1b44043868c398b8fac6" +
		"803aca9175291121c2b0ae26ab55669d55f6b4a1c08e97440f1dd7b7fdb3883f30aa85c08e9e2930b853984a44a7e5b4" +
		"6fdcd64863e14ea1eb037eb9192f7b6dc06448628500e8d163d4206934584d75e80cfa8c542da7751c933e6a538d5d01" +
		"aa23774dc53570aa367158fbc7945691ad773dd466bb8bf2521208cb05e72d07e20c43d9abe7744e03398f43e97bd5fb" +
		"7a8a7483e7a640eda99ff8441f1539a2d14c3928bba031651c6322720b5a089a595577ebc5dac00701919c8ce4c7373a" +
		"4b8924176b8c90f4054f01ec555cb4a31b688b806c23258bb6eb0862b107a0bcc99818d739e5e53b73e155cdd46fac35" +
		"0ec9bab101c80e0bcc9e445a2175f90e46bc8200350fee2a2b44d8a7b4b2625b1b1c063a276238631e9c1bc01a08ab7a" +
		"9db689005bb577bc78a18ed6821ca8219e148a4f1c80224579abb10b931b1a286376715c35529254e4835b075c0b5052" +
		"81361b2cc4e6158df2a1c6ac9d0ee57e79c44f07899bad6ab1c7037eb88094c07a4c3ba131ca60c58cfa4bf60333379c" +
		"9cd1b7924f788e7f44701c40ad5752c53ac04ff69b8439249bdd02b890bb9c79950cfd2552377c58e57b3555f4090e63" +
		"60523b6e555516ef804ecf7a8b7f453c2b8b4f5a15b5ff830f550a44b095753ee7397254322c7a31d8281f281060ecb3" +
		"b5e2f3661d531f22185cf1282fa2a3af7e07c221033eb3201a215a236cb3bedac8357a09018d190a4ca1a4ed8ca5237c" +
		"9ac829b4e1d021eae8903deb558c33048e0b7440e1961c3b450e54bef65b8216ea0b4c9c08aadb2b9766200ff75820eb" +
		"0b4dfb99ce3b2cdbe892e38b92c1fb36e4d41940482db09bc0326187a1571cde677f23a83eda367844eba6f211a4c622" +
		"4338e184fafa3e642616ed65c2bbb7cad6a4b036d0319a62ca0dbc1e3c3874d8c26c0fe701dc0380c697109c68a27580" +
		"0da779930fb1069e50a43b62ba5c578b4e768a5023301ed46023f6be295683f04484f6aa7b883201bc9a2c9f17037845" +
		"450454ae62c5aedfda3a7170240ae27df1c10d8351b91380b73f5a6df5c8003eaa64d27575295162ec77cb45592cd99a" +
		"8f9eabb6cf340e42652476c7a0956800fb88070ee305abd31d8a8c54ff40a6bcd21db3175c893b182aa6b83d164018c7" +
		"b2a1c283c33431351142fd83a461c88477ccb647331c83d8e317b504e88a2410823da77e29559bb1d44c875683155597" +
		"913f6b1240eea7653a96e9226269658cad7513fd4c64797ce95b83bacc2a51d9c1a14644d9670e3f73c4acb0aadb8640" +
		"d6a90ac72c582e50f812daf9a582dbd924013f0b34";

	private uint8[] decode_hex (string hex) {
		var bytes = new uint8[hex.length / 2];
		for (int i = 0; i != bytes.length; i++)
			bytes[i] = (uint8) (hex.substring (i * 2, 2).to_long (null, 16));
		return bytes;
	}
}
