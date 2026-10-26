namespace Idun.Examples {
	private static int main (string[] args) {
		if (args.length < 2) {
			printerr ("Usage: %s <capture.bin> [capture.bin ...]\n", args[0]);
			return 1;
		}

		var ngm = NgmIdentity.load_or_generate (new NgmIdentityStore ());

		if (args.length >= 3 && args[1] == "--kemtest") {
			uint8[] ek;
			FileUtils.get_data (args[2], out ek);
			uint8[] ss = TetraCrypto.kyber_decapsulate (ngm.kem_secret.get_data (), ek);
			print ("idun decapsulate(ek)= %s\n", hexstr (ss));
			return 0;
		}

		if (args.length >= 2 && args[1] == "--ecdhtest") {
			var a = NgmIdentity.generate ();
			var b = NgmIdentity.generate ();
			uint8[] ssa = TetraCrypto.ecdh (a.prekey_key,
				TetraCrypto.decompress_point (b.prekey_compact_key ()));
			uint8[] ssb = TetraCrypto.ecdh (b.prekey_key,
				TetraCrypto.decompress_point (a.prekey_compact_key ()));
			print ("ss_a = %s\n", hexstr (ssa));
			print ("ss_b = %s\n", hexstr (ssb));
			print ("MATCH: %s\n", (hexstr (ssa) == hexstr (ssb)) ? "YES" : "NO");
			return 0;
		}

		if (args.length >= 3 && args[1] == "--dumpprekey") {
			FileUtils.set_data (args[2], ngm.prekey_key.get_data ());
			print ("prekey_point=%s\n", hexstr (ngm.prekey_public_point ()));
			return 0;
		}

		if (args.length >= 2 && args[1] == "--hkdftest") {
			// RFC 5869 Test Case 1 (SHA-256), Expand step.
			uint8[] prk = {
				0x07,0x77,0x09,0x36,0x2c,0x2e,0x32,0xdf,0x0d,0xdc,0x3f,0x0d,0xc4,0x7b,0xba,0x63,
				0x90,0xb6,0xc7,0x3b,0xb5,0x0f,0x9c,0x31,0x22,0xec,0x84,0x4a,0xd7,0xc2,0xb3,0xe5
			};
			uint8[] info = { 0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9 };
			uint8[] okm = TetraCrypto.hkdf_expand ("SHA256", prk, info, 42);
			print ("OKM = %s\n", hexstr (okm));
			print ("WANT= 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865\n");
			return 0;
		}

		if (Environment.get_variable ("IDUN_TESTMKFILE") != null && args.length >= 2 && !args[1].has_prefix("--")) {
			uint8[] raw7; FileUtils.get_data (args[1], out raw7);
			TetraMessage m7 = TetraMessage.unwrap (raw7);
			string mf; FileUtils.get_contents (Environment.get_variable ("IDUN_TESTMKFILE"), out mf);
			int hit=0;
			foreach (unowned string ln in mf.split("\n")) {
				if (ln.length != 64) continue;
				try {
					uint8[] iv7, k7; TetraCrypto.derive_sender_authentication (hexdecode(ln), out iv7, out k7);
					uint8[] pt7 = TetraCrypto.aes_256_ctr (k7, iv7, m7.ciphertext.get_data ());
					if (hexstr(pt7).contains("62706c6973743030")) { print ("MK HIT: %s -> %s\n", ln, hexstr(pt7)[0:96]); hit++; }
				} catch (GLib.Error e) {}
			}
			print ("done, %d hits\n", hit); return 0;
		}

		if (Environment.get_variable ("IDUN_BRUTE") != null && args.length >= 2 && !args[1].has_prefix("--")) {
			uint8[] raw6; FileUtils.get_data (args[1], out raw6);
			TetraMessage m6 = TetraMessage.unwrap (raw6);
			uint8[] ct6 = m6.ciphertext.get_data ();
			string cand; FileUtils.get_contents (Environment.get_variable ("IDUN_BRUTE"), out cand);
			int hit = 0;
			foreach (unowned string ln in cand.split("\n")) {
				if (ln.length != 96) continue;
				try {
					uint8[] pt6 = TetraCrypto.aes_256_ctr (hexdecode(ln.substring(0,64)), hexdecode(ln.substring(64,32)), ct6);
					if (hexstr(pt6).contains("62706c6973743030")) { print ("BRUTE HIT key=%s iv=%s\n  pt=%s\n", ln.substring(0,64), ln.substring(64,32), hexstr(pt6)[0:96]); hit++; }
				} catch (GLib.Error e) {}
			}
			print ("brute done, %d hits\n", hit);
			return 0;
		}

		if (Environment.get_variable ("IDUN_TESTKEYIV") != null && args.length >= 2 && !args[1].has_prefix("--")) {
			uint8[] raw5; FileUtils.get_data (args[1], out raw5);
			TetraMessage m5 = TetraMessage.unwrap (raw5);
			string kv = Environment.get_variable ("IDUN_TESTKEYIV");
			uint8[] key5 = hexdecode (kv.substring(0,64));
			uint8[] iv5 = hexdecode (kv.substring(64,32));
			uint8[] pt5 = TetraCrypto.aes_256_ctr (key5, iv5, m5.ciphertext.get_data ());
			if (hexstr(pt5).contains("62706c6973743030")) print ("KEYIV MATCH: %s\n", hexstr(pt5)[0:80]);
			return 0;
		}

		if (Environment.get_variable ("IDUN_TESTMK") != null && args.length >= 2 && !args[1].has_prefix("--")) {
			uint8[] raw2; FileUtils.get_data (args[1], out raw2);
			TetraMessage m2 = TetraMessage.unwrap (raw2);
			uint8[] mk2 = hexdecode (Environment.get_variable ("IDUN_TESTMK"));
			uint8[] iv4, k4; TetraCrypto.derive_sender_authentication (mk2, out iv4, out k4);
			uint8[] pt4 = TetraCrypto.aes_256_ctr (k4, iv4, m2.ciphertext.get_data ());
			bool ok = hexstr (pt4).contains ("62706c6973743030");
            print ("TESTMK %s -> %s%s\n", Environment.get_variable("IDUN_TESTMK")[0:16], hexstr(pt4)[0:64], ok?"  *** BPLIST MATCH ***":"");
			return 0;
		}

		if (args.length >= 2 && args[1] == "--kemselftest") {
			uint8[] ek;
			uint8[] ss1 = TetraCrypto.kyber_encapsulate (ngm.kem_public_key (), out ek);
			uint8[] ss2 = TetraCrypto.kyber_decapsulate (ngm.kem_secret.get_data (), ek);
			print ("encaps ss = %s\n", hexstr (ss1));
			print ("decaps ss = %s\n", hexstr (ss2));
			print ("MATCH: %s  (sk_len=%u ek_len=%u)\n",
				(hexstr (ss1) == hexstr (ss2)) ? "YES" : "NO",
				ngm.kem_secret.get_data ().length, ek.length);
			return 0;
		}

		if (args.length >= 2 && args[1] == "--identity") {
			print ("prekey_point: %s\n", hexstr (ngm.prekey_public_point ()));
			print ("prekey_compact: %s\n", hexstr (ngm.prekey_compact_key ()));
			print ("kem_public: %s\n", hexstr (ngm.kem_public_key ()));
			print ("signing_compact: %s\n", hexstr (ngm.signing_compact_key ()));
			return 0;
		}

		for (int i = 1; i != args.length; i++) {
			print ("=== %s ===\n", args[i]);
			try {
				uint8[] raw;
				FileUtils.get_data (args[i], out raw);
				decrypt (ngm, raw);
			} catch (GLib.Error e) {
				print ("  failed: %s\n", e.message);
			}
		}
		return 0;
	}

	private static void decrypt (NgmIdentity ngm, uint8[] raw) throws GLib.Error {
		TetraMessage message = TetraMessage.unwrap (raw);
		print ("  index=%" + uint64.FORMAT_MODIFIER + "u encap=%s\n", message.message_index,
			message.kem_encapsulation != null ? "%u".printf (message.kem_encapsulation.length) : "none");

		if (message.kem_encapsulation == null)
			throw new Efni.Error.NOT_SUPPORTED ("no Kyber encapsulation");

		uint8[] ecdh_secret = TetraCrypto.ecdh (ngm.prekey_key,
			TetraCrypto.decompress_point (message.ecdh_public_key.get_data ()));
		uint8[] kem_secret = TetraCrypto.kyber_decapsulate (ngm.kem_secret.get_data (),
			message.kem_encapsulation.get_data ());

		if (Environment.get_variable ("IDUN_DUMP") != null) {
			print ("DUMP index=%" + uint64.FORMAT_MODIFIER + "u\n", message.message_index);
			print ("DUMP our_prekey_compact=%s\n", hexstr (ngm.prekey_compact_key ()));
			print ("DUMP their_ecdh=%s\n", hexstr (message.ecdh_public_key.get_data ()));
			print ("DUMP ecdh_secret=%s\n", hexstr (ecdh_secret));
			print ("DUMP kem_secret=%s\n", hexstr (kem_secret));
			print ("DUMP ciphertext=%s\n", hexstr (message.ciphertext.get_data ()));
			return;
		}

		if (Environment.get_variable ("IDUN_SWEEP") != null) {
			sweep (ngm, message, ecdh_secret, kem_secret, message.message_key_indicator.get_data (), Environment.get_variable ("IDUN_EXPECT"));
			return;
		}

		uint8[] root, chain;
		if (Environment.get_variable ("IDUN_EXACT") != null) {
			// Exact pair-tetra receiver recipe recovered from MessageProtection
			// deriveRootAndChainKeyAsReceiver (macOS 27):
			//   dst  = "TetraStart-" ‖ compact(our_prekey)[32] ‖ compact(their_ecdh)[32]
			//                        ‖ I2OSP(0,4) ‖ I2OSP(0,4)
			//   prk1 = HMAC-SHA384(salt = rootKey|empty, ecdhSS)
			//   prk2 = HMAC-SHA384(salt = prk1,          kemSS)
			//   okm  = HKDF-Expand(prk2, "Tetra-v1.0-RootKeyDerivation-" ‖ dst, 64)
			var dst = new ByteArray ();
			dst.append ("TetraStart-".data);
			dst.append (ngm.prekey_compact_key ());
			dst.append (message.ecdh_public_key.get_data ());
			dst.append ({ 0, 0, 0, 0 });
			dst.append ({ 0, 0, 0, 0 });

			var info = new ByteArray ();
			info.append ("Tetra-v1.0-RootKeyDerivation-".data);
			info.append (dst.data);

			uint8[] prk1 = hmac_sha384 (new uint8[0], ecdh_secret);
			uint8[] prk2 = hmac_sha384 (prk1, kem_secret);
			uint8[] okm = TetraCrypto.hkdf_expand ("SHA384", prk2, info.data, 64);
			uint8[] ek_root = okm[0:32];
			uint8[] ek_chain = okm[32:64];

			// Tetra symmetric ratchet: HKDF-Expand over SHA384.
			uint8[] ck = ek_chain;
			for (uint64 n = 0; n != message.message_index; n++)
				ck = TetraCrypto.hkdf_expand ("SHA384", ck,
					"Tetra-v1.0-SymmetricRatchet-ChainKeyDerivation".data, 32);
			uint8[] mk = TetraCrypto.hkdf_expand ("SHA384", ck,
				"Tetra-v1.0-SymmetricRatchet-MessageKeyDerivation".data, 32);

			// Tetra sender-authentication layer: AES-256-CTR. (iv, key) = one
			// SHA384 expand over "Tetra-v1.0-SymmetricLayer-AES-CTR-Keying",
			// split iv[0:16] ‖ key[16:48]. CoreCryptoAESCTRImpl.crypt.
			uint8[] iv2, ck2;
			TetraCrypto.derive_sender_authentication (mk, out iv2, out ck2);
			print ("  [exact] root=%s mk=%s iv=%s key=%s ctlen=%u\n",
				hexstr (ek_root)[0:16], hexstr (mk)[0:16], hexstr (iv2),
				hexstr (ck2)[0:16], message.ciphertext.length);
			uint8[] padded2 = TetraCrypto.aes_256_ctr (ck2, iv2, message.ciphertext.get_data ());
			print ("  [exact] CTR plaintext %u bytes: %s\n", padded2.length, hexstr (padded2)[0:96]);
			print_summary (padded2);
			return;
		} else if (Environment.get_variable ("IDUN_CASCADE2") != null) {
			// transcript = dst ‖ I2OSP-framed public keys; cascaded extract(ecdh), extract(kem); expand(info)
			string dst = Environment.get_variable ("IDUN_DST") ?? "TetraStart-";
			uint8[] their_ecdh = message.ecdh_public_key.get_data ();
			uint8[] our_ecdh = ngm.prekey_compact_key ();
			uint8[] kem_pub = ngm.kem_public_key ();
			var t = new ByteArray ();
			t.append (dst.data);
			foreach (unowned string tok in (Environment.get_variable ("IDUN_TS") ?? "their,our").split (",")) {
				uint8[] k = (tok == "their") ? their_ecdh : (tok == "our") ? our_ecdh
					: (tok == "kem") ? kem_pub : (tok == "encap") ? message.kem_encapsulation.get_data () : new uint8[0];
				if (tok == "z") { t.append ({0,0,0,0}); continue; }
				t.append ({ (uint8)(k.length>>24),(uint8)(k.length>>16),(uint8)(k.length>>8),(uint8)k.length });
				t.append (k);
			}
			bool kemfirst = Environment.get_variable ("IDUN_KEMFIRST") != null;
			uint8[] s1 = kemfirst ? kem_secret : ecdh_secret;
			uint8[] s2 = kemfirst ? ecdh_secret : kem_secret;
			uint8[] salt0 = (Environment.get_variable ("IDUN_SALT_T") != null) ? t.data : new uint8[0];
			uint8[] prk1 = hmac_sha384 (salt0, s1);
			uint8[] prk2 = hmac_sha384 (prk1, s2);
			uint8[] expinfo = (Environment.get_variable ("IDUN_SALT_T") != null)
				? "Tetra-v1.0-RootKeyDerivation-".data : t.data;
			uint8[] okm = TetraCrypto.hkdf_expand ("SHA384", prk2, expinfo, 64);
			root = okm[0:32]; chain = okm[32:64];
		} else if (Environment.get_variable ("IDUN_CASCADE") != null) {
			string info = Environment.get_variable ("IDUN_INFO") ?? "Tetra-v1.0-RootKeyDerivation-";
			uint8[] prk1 = hmac_sha384 (new uint8[0], ecdh_secret);
			uint8[] prk2 = hmac_sha384 (prk1, kem_secret);
			uint8[] okm = TetraCrypto.hkdf_expand ("SHA384", prk2, info.data, 64);
			root = okm[0:32];
			chain = okm[32:64];
		} else {
			string? mode = Environment.get_variable ("IDUN_DERIVE");
			uint8[] use_ecdh = (mode == "kemonly") ? new uint8[0] : ecdh_secret;
			uint8[]? use_kem = (mode == "ecdhonly") ? null : kem_secret;
			string dst = Environment.get_variable ("IDUN_DST") ?? "TetraStart-";
			TetraCrypto.derive_root_and_chain (new uint8[0], use_ecdh, use_kem,
				dst.data, out root, out chain);
		}

		uint8[] chain_key = chain;
		for (uint64 n = 0; n != message.message_index; n++)
			chain_key = TetraCrypto.advance_chain_key (chain_key);
		uint8[] message_key = TetraCrypto.derive_message_key (chain_key);

		print ("  ecdh_point_len=%u ecdh_secret=%s kem_secret=%s chain=%s\n",
			message.ecdh_public_key.length, hexstr (ecdh_secret)[0:16], hexstr (kem_secret)[0:16],
			hexstr (chain)[0:16]);

		uint8[] iv, cipher_key;
		TetraCrypto.derive_sender_authentication (message_key, out iv, out cipher_key);
		uint8[] padded = TetraCrypto.aes_256_ctr (cipher_key, iv, message.ciphertext.get_data ());
		print ("  padded_head=%s\n", hexstr (padded)[0:48]);

		uint8[] plaintext = TetraInnerMessage.parse (padded).plaintext.get_data ();
		print ("  DECRYPTED %u bytes\n", plaintext.length);
		print_summary (plaintext);
	}

	private static uint8[] hmac_hash (ChecksumType ct, int outlen, uint8[] key, uint8[] data) {
		var h = new Hmac (ct, key);
		h.update (data);
		var o = new uint8[outlen];
		size_t n = o.length;
		h.get_digest (o, ref n);
		return o;
	}

	private static uint8[] cat (uint8[]? a, uint8[]? b) {
		var r = new ByteArray ();
		if (a != null) r.append (a);
		if (b != null) r.append (b);
		return r.data;
	}

	private static void sweep (NgmIdentity ngm, TetraMessage message, uint8[] ecdh, uint8[] kem, uint8[]? want_indicator, string? want_expect) {
		uint8[] our = ngm.prekey_compact_key ();
		uint8[] their = message.ecdh_public_key.get_data ();
		uint8[] ct = message.ciphertext.get_data ();
		uint8[] z8 = { 0, 0, 0, 0, 0, 0, 0, 0 };
		uint8[] root_info = "Tetra-v1.0-RootKeyDerivation-".data;
		uint8[] start = "TetraStart-".data;
		uint8[] sr_msg = "Tetra-v1.0-SymmetricRatchet-MessageKeyDerivation".data;
		uint8[] paddy_key = "Paddy-v1.0-SymmetricLayer-AES-GCM-Key".data;
		uint8[] paddy_nonce = "Paddy-v1.0-SymmetricLayer-AES-GCM-Nonce".data;

		var dsts = new Gee.ArrayList<Bytes> ();
		var dst_names = new Gee.ArrayList<string> ();
		dsts.add (new Bytes (cat (cat (start, cat (our, their)), z8)));  dst_names.add ("start+our+their+z8");
		dsts.add (new Bytes (cat (cat (start, cat (their, our)), z8)));  dst_names.add ("start+their+our+z8");
		dsts.add (new Bytes (cat (start, cat (our, their))));            dst_names.add ("start+our+their");
		dsts.add (new Bytes (cat (start, cat (their, our))));            dst_names.add ("start+their+our");

		print ("SWEEP target indicator(field9)=%s index=%llu ct=%u\n", (want_indicator!=null)?hexstr(want_indicator):"NULL", message.message_index, ct.length);
		int[] hashes = { 384, 256 };
		int tried = 0;
		int best_score = -1;
		string best = "(none)";

		for (int di = 0; di < dsts.size; di++) {
			uint8[] dst = dsts[di].get_data ();
			var infos = new Gee.ArrayList<Bytes> ();
			var info_names = new Gee.ArrayList<string> ();
			infos.add (new Bytes (cat (root_info, dst))); info_names.add ("rootinfo+dst");
			infos.add (new Bytes (cat (dst, root_info))); info_names.add ("dst+rootinfo");
			infos.add (new Bytes (dst));                  info_names.add ("dst");
			infos.add (new Bytes (root_info));            info_names.add ("rootinfo");

			foreach (int rh in hashes) {
				ChecksumType rct = (rh == 384) ? ChecksumType.SHA384 : ChecksumType.SHA256;
				int rlen = (rh == 384) ? 48 : 32;
				string rdig = (rh == 384) ? "SHA384" : "SHA256";

				// KEM-secret processing variants (Apple may hash the KEM ss, or the
				// establishing root may be ECDH-only).
				var kems = new Gee.ArrayList<Bytes> ();
				var kem_names = new Gee.ArrayList<string> ();
				kems.add (new Bytes (kem)); kem_names.add ("raw");
				try { kems.add (new Bytes (TetraCrypto.hkdf_expand ("SHA256", kem, new uint8[0], 32))); kem_names.add ("exp256"); } catch (GLib.Error e) {}
				try { kems.add (new Bytes (TetraCrypto.hkdf_expand ("SHA384", kem, new uint8[0], 32))); kem_names.add ("exp384"); } catch (GLib.Error e) {}
				{ var h = new Checksum (ChecksumType.SHA256); h.update (kem, kem.length); uint8[] o = new uint8[32]; size_t n = o.length; h.get_digest (o, ref n); kems.add (new Bytes (o)); kem_names.add ("sha256"); }
				kems.add (new Bytes (new uint8[0])); kem_names.add ("none");

				var prks = new Gee.ArrayList<Bytes> ();
				var prk_names = new Gee.ArrayList<string> ();
				for (int ki = 0; ki < kems.size; ki++) {
					uint8[] kv = kems[ki].get_data ();
					uint8[] p1 = hmac_hash (rct, rlen, new uint8[0], ecdh);
					prks.add (new Bytes (hmac_hash (rct, rlen, p1, kv))); prk_names.add ("casc ecdh,kem[%s]".printf (kem_names[ki]));
					uint8[] q1 = hmac_hash (rct, rlen, new uint8[0], kv);
					prks.add (new Bytes (hmac_hash (rct, rlen, q1, ecdh))); prk_names.add ("casc kem[%s],ecdh".printf (kem_names[ki]));
				}

				for (int pi = 0; pi < prks.size; pi++) {
					for (int ii = 0; ii < infos.size; ii++) {
						uint8[] okm;
						try {
							okm = TetraCrypto.hkdf_expand (rdig, prks[pi].get_data (), infos[ii].get_data (), 64);
						} catch (GLib.Error e) { continue; }
						uint8[] rootk = okm[0:32];
						uint8[] chain = okm[32:64];

						// try chain-half = okm[32:64] (chain) and okm[0:32] (root), as the ratchet base
						string[] base_names = { "chainhalf", "roothalf" };
						for (int bh = 0; bh < 2; bh++) {
							uint8[] basek = (bh == 0) ? chain : rootk;
							foreach (int sh in hashes) {
								string sdig = (sh == 384) ? "SHA384" : "SHA256";
								uint8[] mkexp;
								try {
									mkexp = TetraCrypto.hkdf_expand (sdig, basek, sr_msg, 32);
								} catch (GLib.Error e) { continue; }

								var mks = new Gee.ArrayList<Bytes> ();
								var mk_names = new Gee.ArrayList<string> ();
								mks.add (new Bytes (mkexp)); mk_names.add ("mkexp");
								mks.add (new Bytes (basek)); mk_names.add ("base");

								for (int mi = 0; mi < mks.size; mi++) {
									uint8[] mkc = mks[mi].get_data ();
									// Known-plaintext oracle: CTR-decrypt and look for expected bytes.
									if (want_expect != null) {
										try {
											uint8[] iv3, k3;
											TetraCrypto.derive_sender_authentication (mkc, out iv3, out k3);
											uint8[] pt3 = TetraCrypto.aes_256_ctr (k3, iv3, ct);
											if (hexstr (pt3).contains (want_expect)) {
												print ("\n*** PLAINTEXT MATCH ***\n  dst=%s rh=%d prk=%s info=%s base=%s sh=%d mk=%s\n  pt=%s\n",
													dst_names[di], rh, prk_names[pi], info_names[ii], base_names[bh], sh, mk_names[mi], hexstr (pt3));
												best_score = 999;
											}
										} catch (GLib.Error e) {}
									}
									// Oracle: messageKeyIndicator (exact 16-byte match against field 9).
									foreach (int ph in hashes) {
										string pdig = (ph == 384) ? "SHA384" : "SHA256";
										uint8[] indic;
										try {
											indic = TetraCrypto.hkdf_expand (pdig, mkc,
												"Tetra-v1.0-SymmetricLayer-MessageKeyIndicator".data, 16);
										} catch (GLib.Error e) { continue; }
										tried++;
										if (want_indicator != null && hexstr (indic) == hexstr (want_indicator)) {
											print ("\n*** INDICATOR MATCH ***\n");
											print ("  dst=%s rh=%d prk=%s info=%s base=%s sh=%d mk=%s ph=%d\n",
												dst_names[di], rh, prk_names[pi], info_names[ii], base_names[bh],
												sh, mk_names[mi], ph);
											print ("  messageKey=%s\n", hexstr (mkc));
											best_score = 999;
										}
									}
								}
							}
						}
					}
				}
			}
		}
		print ("sweep done, %d PEEK attempts\n", tried);
		print ("BEST score %d: %s\n", best_score, best);
	}

	private static uint8 hexnib (char c) { if (c>='0'&&c<='9') return (uint8)(c-'0'); if (c>='a'&&c<='f') return (uint8)(c-'a'+10); if (c>='A'&&c<='F') return (uint8)(c-'A'+10); return 0; }
	private static uint8[] hexdecode (string h) { var o=new uint8[h.length/2]; for(int i=0;i<o.length;i++) o[i]=(uint8)(hexnib(h[i*2])*16+hexnib(h[i*2+1])); return o; }

	private static uint8[] hmac_sha384 (uint8[] key, uint8[] data) {
		var h = new Hmac (ChecksumType.SHA384, key);
		h.update (data);
		var o = new uint8[48];
		size_t n = o.length;
		h.get_digest (o, ref n);
		return o;
	}

	private static string hexstr (uint8[] d) {
		var sb = new StringBuilder ();
		foreach (uint8 b in d) sb.append_printf ("%02x", b);
		return sb.str;
	}

	private static void print_summary (uint8[] plaintext) {
		uint n = uint.min (plaintext.length, 64);
		var sb = new StringBuilder ("  head: ");
		for (uint i = 0; i != n; i++)
			sb.append_printf ("%02x", plaintext[i]);
		print ("%s\n", sb.str);
		bool printable = plaintext.length > 8 && plaintext[0] == 'b' && plaintext[1] == 'p';
		if (printable)
			print ("  looks like a binary plist (bplist)\n");
	}
}
