using Efni;

namespace Idun.EscrowSrpTest {
	public void add_tests () {
		GLib.Test.add_func ("/EscrowSrp/srp-agrees-with-server", srp_agrees_with_server);
		GLib.Test.add_func ("/EscrowSrp/key-vault-round-trips", key_vault_round_trips);
		GLib.Test.add_func ("/EscrowSrp/recovers-bottle-entropy", recovers_bottle_entropy);
	}

	private const string N_HEX =
		"AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
		"A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
		"E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
		"55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
		"CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
		"544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
		"AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
		"94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

	// A standalone SRP-6a verifier side, built independently of the client, that produces a
	// challenge and derives the session key the way Apple's escrow proxy does. If idun's client
	// lands on the same K from the challenge, the client's SRP arithmetic is correct.
	private static void srp_agrees_with_server () {
		try {
			uint8[] username = "0000000000".data;
			uint8[] password = "123456".data;
			uint8[] salt = random_bytes (16);

			var client = new EscrowSrpSession ();
			uint8[] a_pub = client.public_a ();

			var ctx = new OpenSSL.BigNumberContext.secure ();
			var n = new OpenSSL.BigNumber.from_big_endian (decode_hex (N_HEX));
			var g = new OpenSSL.BigNumber.from_big_endian ({ 2 });

			// x = H(salt || H(user:pass)); v = g^x
			var x = new OpenSSL.BigNumber.from_big_endian (
				sha256 (join (salt, sha256 (join (username, join (":".data, password))))));
			var v = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mod_exp (v, g, x, n, ctx);

			// k = H(PAD(N) || PAD(g)); B = (k*v + g^b) mod N
			var k = new OpenSSL.BigNumber.from_big_endian (sha256 (join (pad (n), pad (g))));
			var b = new OpenSSL.BigNumber.from_big_endian (random_bytes (32));
			var kv = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mul (kv, k, v, ctx);
			var gb = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mod_exp (gb, g, b, n, ctx);
			var b_pub = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.add (b_pub, kv, gb);
			OpenSSL.BigNumber.mod_nonneg (b_pub, b_pub, n, ctx);
			uint8[] b_pub_bytes = trim (b_pub);

			client.process (username, password, salt, b_pub_bytes);

			// Server side: u = H(trim(A) || trim(B)); S = (A * v^u)^b; K = H(trim(S)).
			var a_big = new OpenSSL.BigNumber.from_big_endian (a_pub);
			var u = new OpenSSL.BigNumber.from_big_endian (sha256 (join (a_pub, b_pub_bytes)));
			var vu = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mod_exp (vu, v, u, n, ctx);
			var avu = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mul (avu, a_big, vu, ctx);
			OpenSSL.BigNumber.mod_nonneg (avu, avu, n, ctx);
			var s = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mod_exp (s, avu, b, n, ctx);
			uint8[] server_key = sha256 (trim (s));

			assert_true (client.shared_key.length == 32);
			assert_true (equal (client.shared_key, server_key));
		} catch (GLib.Error e) {
			GLib.error ("srp round-trip failed: %s", e.message);
		}
	}

	private static void key_vault_round_trips () {
		try {
			uint8[] header = random_bytes (24);
			var builder = new EscrowKeyVault (header);
			uint8[] s0 = random_bytes (7);
			uint8[] s1 = random_bytes (32);
			builder.add_section_padded (s0, 20);
			builder.add_section (s1);
			uint8[] packed = builder.pack ();

			uint8[] out_header;
			Bytes[] sections = EscrowKeyVault.unpack (packed, 24, 2, out out_header);
			assert_true (equal (out_header, header));
			// The padded section occupies a fixed 20-byte slot on the wire, but its length prefix
			// still delimits the real 7-byte payload, so unpack yields exactly what went in.
			assert_true (equal (sections[0].get_data (), s0));
			assert_true (equal (sections[1].get_data (), s1));
		} catch (GLib.Error e) {
			GLib.error ("key vault round-trip failed: %s", e.message);
		}
	}

	// Build a record the way the escrow proxy seals it (outer AES-256-CBC under the SRP key K,
	// inner PBKDF2 + AES-128-CBC under the passcode) and confirm the recovery path unwraps it to
	// the original bottled entropy.
	private static void recovers_bottle_entropy () {
		try {
			uint8[] passcode = "123456".data;
			uint8[] entropy = random_bytes (72);
			uint8[] shared_key = random_bytes (32);
			uint8[] server_proof = random_bytes (32);

			var bottle = new Plist ();
			bottle.set_bytes ("BottledPeerEntropy", new Bytes (entropy));
			uint8[] bottle_plist = bottle.to_binary ();

			int rounds = 1000;
			uint8[] salt2 = random_bytes (20);
			uint8[] inner_key = OctagonCrypto.pbkdf2_sha256 (passcode, salt2, rounds, 16);
			uint8[] inner_ct = OctagonCrypto.aes_cbc_encrypt (inner_key, salt2[0 : 16], bottle_plist);

			var inner_header = new uint8[16];
			inner_header[8] = (uint8) ((rounds >> 24) & 0xff);
			inner_header[9] = (uint8) ((rounds >> 16) & 0xff);
			inner_header[10] = (uint8) ((rounds >> 8) & 0xff);
			inner_header[11] = (uint8) (rounds & 0xff);
			var inner = new EscrowKeyVault (inner_header);
			inner.add_section (new uint8[0]);   // 0
			inner.add_section (salt2);          // 1
			inner.add_section (new uint8[0]);   // 2
			inner.add_section (inner_ct);       // 3
			inner.add_section (new uint8[0]);   // 4
			inner.add_section (new uint8[0]);   // 5
			uint8[] inner_blob = inner.pack ();

			uint8[] iv = random_bytes (16);
			uint8[] outer_ct = OctagonCrypto.aes_cbc_encrypt (shared_key, iv, inner_blob);
			var outer_header = new uint8[24];   // version 0 at [4:8] is already zero
			var outer = new EscrowKeyVault (outer_header);
			outer.add_section (server_proof);   // 0 = M2
			outer.add_section (iv);             // 1
			outer.add_section (outer_ct);       // 2
			uint8[] response_blob = outer.pack ();

			Bytes recovered = EscrowProxyClient.decrypt_recovered_record (shared_key, server_proof,
				0, response_blob, passcode);
			assert_true (equal (recovered.get_data (), entropy));
		} catch (GLib.Error e) {
			GLib.error ("bottle recovery failed: %s", e.message);
		}
	}

	private static uint8[] random_bytes (int length) {
		var bytes = new uint8[length];
		OpenSSL.Rng.generate (bytes);
		return bytes;
	}

	private static bool equal (uint8[] a, uint8[] b) {
		if (a.length != b.length)
			return false;
		return Memory.cmp (a, b, a.length) == 0;
	}

	private static uint8[] join (uint8[] a, uint8[] b) {
		var result = new uint8[a.length + b.length];
		Memory.copy (result, a, a.length);
		Memory.copy ((uint8 *) result + a.length, b, b.length);
		return result;
	}

	private static uint8[] sha256 (uint8[] data) {
		var checksum = new Checksum (ChecksumType.SHA256);
		checksum.update (data, data.length);
		var digest = new uint8[32];
		size_t length = digest.length;
		checksum.get_digest (digest, ref length);
		return digest;
	}

	private static uint8[] pad (OpenSSL.BigNumber value) {
		var buffer = new uint8[256];
		value.to_big_endian_padded (buffer);
		return buffer;
	}

	private static uint8[] trim (OpenSSL.BigNumber value) {
		var buffer = new uint8[value.num_bytes ()];
		value.to_big_endian (buffer);
		return buffer;
	}

	private static uint8[] decode_hex (string hex) {
		var bytes = new uint8[hex.length / 2];
		for (int i = 0; i != bytes.length; i++)
			bytes[i] = (uint8) hex.substring (i * 2, 2).to_long (null, 16);
		return bytes;
	}
}
