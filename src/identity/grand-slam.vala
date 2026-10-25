using Efni;

namespace Idun {
	/**
	 * Grand Slam authentication: signs into an Apple ID over SRP-6a and returns the
	 * IDMS provisioning tokens the identity services build on, including the PET that
	 * authorizes IDS delegate login. Idun drives the exchange itself and only asks the
	 * identity oracle for the anisette the servers expect.
	 */
	public sealed class GrandSlam : Object {
		public IdentityOracle oracle {
			get;
			construct;
		}

		private const string SERVICE_URL = "https://gsa.apple.com/grandslam/GsService2";
		private const string PET_NAME = "com.apple.gs.idms.pet";

		private const string N_HEX =
			"AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
			"A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
			"E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
			"55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
			"CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
			"544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
			"AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
			"94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

		public GrandSlam (IdentityOracle oracle) {
			Object (oracle: oracle);
		}

		construct {
			trust.guard (session);
		}

		public async GrandSlamIdentity authenticate (string username, string password, Bytes push_token,
				TwoFactorProvider? two_factor = null, Cancellable? cancellable = null) throws Efni.Error, IOError {
			Gee.Map<string, string> device = yield fetch_device (push_token, cancellable);
			yield fetch_auth_mode (username, device, cancellable);
			PlistDict spd = yield run_login (username, password, device, cancellable);

			if (requires_two_factor (spd)) {
				if (two_factor == null)
					throw new Efni.Error.NOT_SUPPORTED ("Two-factor authentication is required");
				yield elevate_with_two_factor (spd, two_factor, device, cancellable);
				device = yield fetch_device (push_token, cancellable);
				spd = yield run_login (username, password, device, cancellable);
			}

			return extract_identity (spd);
		}

		private static string current_timestamp () {
			return new DateTime.now_utc ().format ("%Y-%m-%dT%H:%M:%SZ");
		}

		private async Gee.Map<string, string> fetch_device (Bytes push_token, Cancellable? cancellable)
				throws Efni.Error, IOError {
			Gee.Map<string, string> device = yield oracle.fetch_anisette (cancellable);
			Gee.Map<string, string> attestation = yield oracle.fetch_baa_headers (cancellable);
			foreach (var entry in attestation.entries)
				device[entry.key] = entry.value;
			device["ptkn"] = upper_hex (push_token.get_data ());
			return device;
		}

		private static string upper_hex (uint8[] data) {
			var builder = new StringBuilder ();
			foreach (uint8 b in data)
				builder.append_printf ("%02X", b);
			return builder.str;
		}

		private async void fetch_auth_mode (string username, Gee.Map<string, string> device,
				Cancellable? cancellable) throws Efni.Error, IOError {
			var message = new Soup.Message ("GET", SERVICE_URL + "/fetchAuthMode");
			var headers = message.request_headers;
			headers.replace ("X-Apple-AK-Context-Type", "facetime");
			headers.replace ("X-Apple-AK-DataRecoveryService-Status", "1");
			headers.replace ("X-Apple-Client-App-Name", "FaceTime");
			headers.replace ("X-Apple-I-AppleID", username);
			headers.replace ("X-Apple-I-Client-Bundle-Id", "com.apple.FaceTime");
			headers.replace ("X-Apple-I-Device-Configuration-Mode", "0");
			headers.replace ("X-Apple-I-DeviceUserMode", "0");
			headers.replace ("X-Apple-I-Flow-Id", Uuid.string_random ().up ());
			headers.replace ("X-Apple-I-LiveOnServerBackoffOptIn", "0");
			headers.replace ("X-Apple-I-Service-Type", "facetime");
			headers.replace ("X-Apple-I-Locale", "en_US@rg=nozzzz");
			headers.replace ("X-Apple-I-MLB", device["X-Apple-I-MLB"]);
			headers.replace ("X-Apple-I-ROM", device["X-Apple-I-ROM"]);
			headers.replace ("X-Apple-I-SRL-NO", device["X-Apple-I-SRL-NO"]);
			headers.replace ("X-Apple-I-Provisioning-Device-Id", device["X-Apple-I-SDID"]);
			headers.replace ("X-Apple-I-TimeZone", "GMT");
			headers.replace ("X-Apple-I-TimeZone-Offset", "0");
			headers.replace ("X-Apple-Requested-Partition", "0");
			headers.replace ("X-MMe-Client-Info", device["X-MMe-Client-Info"]);
			headers.replace ("X-Mme-Device-Id", device["X-Mme-Device-Id"]);
			yield send_raw (message, cancellable);
		}

		private static bool requires_two_factor (PlistDict spd) throws Efni.Error {
			try {
				return spd.has ("status-code") && spd.get_integer ("status-code") == 409;
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed Grand Slam login response: %s", e.message);
			}
		}

		private async PlistDict run_login (string username, string password,
				Gee.Map<string, string> anisette, Cancellable? cancellable) throws Efni.Error, IOError {
			var ctx = new OpenSSL.BigNumberContext.secure ();
			var n = bn_from (decode_hex (N_HEX));
			var g = bn_from ({ 2 });

			var secret = new uint8[32];
			OpenSSL.Rng.generate (secret);
			var a = bn_from (secret);
			var pub = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mod_exp (pub, g, a, n, ctx);

			var init_request = new PlistDict ();
			init_request.set_string ("u", username);
			init_request.set_string ("o", "init");
			var methods = new PlistArray ();
			methods.add_string ("s2k");
			methods.add_string ("s2k_fo");
			init_request.set_array ("ps", methods);
			init_request.set_bytes ("A2k", new Bytes (bn_to_padded (pub)));
			init_request.set_dict ("cpd", build_cpd (anisette));

			PlistDict init = yield exchange (init_request, anisette, cancellable);

			uint8[] salt;
			string cookie;
			OpenSSL.BigNumber peer;
			int64 iterations;
			string protocol;
			try {
				salt = init.get_bytes ("s").get_data ();
				peer = bn_from (init.get_bytes ("B").get_data ());
				iterations = init.get_integer ("i");
				cookie = init.get_string ("c");
				protocol = init.get_string ("sp");
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed Grand Slam init response: %s", e.message);
			}

			uint8[] verifier = derive_verifier (password, salt, (int) iterations, protocol);
			uint8[] scramble = hash ({ new Bytes (bn_to_padded (pub)), new Bytes (bn_to_padded (peer)) });
			var x = bn_from (hash ({ new Bytes (salt), new Bytes (hash ({ new Bytes (":".data), new Bytes (verifier) })) }));

			var session_key = compute_session_key (n, g, a, pub, peer, x, bn_from (scramble), ctx);
			uint8[] proof = compute_client_proof (n, g, username, salt, pub, peer, session_key);

			var complete_request = new PlistDict ();
			complete_request.set_string ("u", username);
			complete_request.set_string ("o", "complete");
			complete_request.set_string ("c", cookie);
			complete_request.set_bytes ("M1", new Bytes (proof));
			complete_request.set_dict ("cpd", build_cpd (anisette));

			PlistDict complete = yield exchange (complete_request, anisette, cancellable);

			uint8[] expected = hash ({ new Bytes (bn_to_bytes (pub)), new Bytes (proof), new Bytes (session_key) });
			try {
				if (!constant_time_equal (complete.get_bytes ("M2").get_data (), expected))
					throw new Efni.Error.PROTOCOL ("Grand Slam server proof mismatch");
				return decrypt_session_data (complete.get_bytes ("spd").get_data (), session_key);
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed Grand Slam complete response: %s", e.message);
			}
		}

		private uint8[] compute_session_key (OpenSSL.BigNumber n, OpenSSL.BigNumber g, OpenSSL.BigNumber a,
				OpenSSL.BigNumber pub, OpenSSL.BigNumber peer, OpenSSL.BigNumber x, OpenSSL.BigNumber scramble,
				OpenSSL.BigNumberContext ctx) {
			var multiplier = bn_from (hash ({ new Bytes (bn_to_padded (n)), new Bytes (bn_to_padded (g)) }));

			var gx = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mod_exp (gx, g, x, n, ctx);
			var scaled = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mul (scaled, multiplier, gx, ctx);
			var difference = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.sub (difference, peer, scaled);
			var residue = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mod_nonneg (residue, difference, n, ctx);

			var blinded = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mul (blinded, scramble, x, ctx);
			var exponent = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.add (exponent, a, blinded);

			var premaster = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mod_exp (premaster, residue, exponent, n, ctx);
			return hash ({ new Bytes (bn_to_bytes (premaster)) });
		}

		private uint8[] compute_client_proof (OpenSSL.BigNumber n, OpenSSL.BigNumber g, string username,
				uint8[] salt, OpenSSL.BigNumber pub, OpenSSL.BigNumber peer, uint8[] session_key) {
			uint8[] hn = hash ({ new Bytes (bn_to_bytes (n)) });
			uint8[] hg = hash ({ new Bytes (bn_to_padded (g)) });
			var fingerprint = new uint8[hn.length];
			for (int i = 0; i != hn.length; i++)
				fingerprint[i] = hn[i] ^ hg[i];

			return hash ({ new Bytes (fingerprint), new Bytes (hash ({ new Bytes (username.data) })), new Bytes (salt),
				new Bytes (bn_to_bytes (pub)), new Bytes (bn_to_bytes (peer)), new Bytes (session_key) });
		}

		private uint8[] derive_verifier (string password, uint8[] salt, int iterations, string protocol) {
			uint8[] digest = hash ({ new Bytes (password.data) });
			if (protocol != "s2k_fo")
				return pbkdf2_sha256 (digest, salt, iterations, 32);
			return pbkdf2_sha256 (bin_to_hex (digest).data, salt, iterations, 32);
		}

		private PlistDict decrypt_session_data (uint8[] ciphertext, uint8[] session_key) throws Efni.Error {
			uint8[] key = hmac_sha256 (session_key, "extra data key:".data);
			uint8[] iv = hmac_sha256 (session_key, "extra data iv:".data)[0:16];
			uint8[] plain = aes_256_cbc_decrypt (key, iv, ciphertext);

			try {
				var plist = new Plist.from_data (plain);
				return plist;
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed Grand Slam session data: %s", e.message);
			}
		}

		private GrandSlamIdentity extract_identity (PlistDict spd) throws Efni.Error {
			try {
				PlistDict tokens = spd.get_dict ("t");
				PlistDict pet = tokens.get_dict (PET_NAME);
				return new GrandSlamIdentity (spd.get_string ("adsid"), spd.get_integer ("DsPrsId").to_string (),
					pet.get_string ("token"), pet.get_integer ("expiry"));
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Grand Slam response missing tokens: %s", e.message);
			}
		}

		private async void elevate_with_two_factor (PlistDict spd, TwoFactorProvider two_factor,
				Gee.Map<string, string> anisette, Cancellable? cancellable) throws Efni.Error, IOError {
			string token;
			try {
				token = Base64.encode (@"$(spd.get_string ("adsid")):$(spd.get_string ("GsIdmsToken"))".data);
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Grand Slam response missing trust tokens: %s", e.message);
			}

			yield request_two_factor_code (token, anisette, cancellable);
			string code = yield two_factor.request_security_code (cancellable);
			yield submit_two_factor_code (token, code, anisette, cancellable);
		}

		private async void request_two_factor_code (string identity_token, Gee.Map<string, string> anisette,
				Cancellable? cancellable) throws Efni.Error, IOError {
			var message = new Soup.Message ("GET", "https://gsa.apple.com/auth/verify/trusteddevice");
			apply_two_factor_headers (message, identity_token, anisette);
			yield send_raw (message, cancellable);
		}

		private async void submit_two_factor_code (string identity_token, string code,
				Gee.Map<string, string> anisette, Cancellable? cancellable) throws Efni.Error, IOError {
			var message = new Soup.Message ("GET", "https://gsa.apple.com/grandslam/GsService2/validate");
			apply_two_factor_headers (message, identity_token, anisette);
			message.request_headers.replace ("security-code", code);

			Bytes response = yield send_raw (message, cancellable);
			try {
				int64 code_result = new Plist.from_data (response.get_data ()).get_integer ("ec");
				if (code_result != 0) {
					throw new Efni.Error.PROTOCOL ("Two-factor validation failed: %" + int64.FORMAT_MODIFIER + "d",
						code_result);
				}
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed two-factor validation response: %s", e.message);
			}
		}

		private void apply_two_factor_headers (Soup.Message message, string identity_token,
				Gee.Map<string, string> anisette) {
			foreach (var entry in anisette.entries)
				message.request_headers.replace (entry.key, entry.value);
			message.request_headers.replace ("Accept", "text/x-xml-plist");
			message.request_headers.replace ("Content-Type", "text/x-xml-plist");
			message.request_headers.replace ("User-Agent", "Xcode");
			message.request_headers.replace ("X-Apple-Identity-Token", identity_token);
			message.request_headers.replace ("X-Apple-App-Info", "com.apple.gs.xcode.auth");
			message.request_headers.replace ("X-Xcode-Version", "11.2 (11B41)");
		}

		private async PlistDict exchange (PlistDict request, Gee.Map<string, string> device,
				Cancellable? cancellable) throws Efni.Error, IOError {
			var header = new PlistDict ();
			header.set_string ("Version", "1.0.1");
			var envelope = new Plist ();
			envelope.set_dict ("Header", header);
			envelope.set_dict ("Request", request);

			var message = new Soup.Message ("POST", SERVICE_URL);
			message.set_request_body_from_bytes ("text/x-xml-plist", new Bytes (envelope.to_xml ().data));
			var headers = message.request_headers;
			headers.replace ("User-Agent", device["X-MMe-Client-Info"]);
			headers.replace ("X-MMe-Client-Info", device["X-MMe-Client-Info"]);
			headers.replace ("X-Mme-Device-Id", device["X-Mme-Device-Id"]);
			headers.replace ("X-Apple-AK-Context-Type", "facetime");
			headers.replace ("X-Apple-Client-App-Name", "FaceTime");
			headers.replace ("X-Apple-I-Auth-Type", "2");
			headers.replace ("X-Apple-I-Client-Bundle-Id", "com.apple.FaceTime");
			headers.replace ("X-Apple-I-MD", device["X-Apple-I-MD"]);
			headers.replace ("X-Apple-I-MD-M", device["X-Apple-I-MD-M"]);
			headers.replace ("X-Apple-I-MD-RINFO", device["X-Apple-I-MD-RINFO"]);
			headers.replace ("X-Apple-I-MD-LU", device["X-Apple-I-MD-LU"]);
			headers.replace ("X-Apple-I-SDID", device["X-Apple-I-SDID"]);
			headers.replace ("X-Apple-I-Stable-ID", device["X-Apple-I-Stable-ID"]);
			headers.replace ("X-Apple-I-LDUID", device["X-Apple-I-LDUID"]);
			headers.replace ("x-apple-i-device-type", device["x-apple-i-device-type"]);
			headers.replace ("x-apple-baa-cert", device["x-apple-baa-cert"]);
			headers.replace ("x-apple-baa-sig", device["x-apple-baa-sig"]);
			headers.replace ("x-apple-baa-sig-alt", device["x-apple-baa-sig-alt"]);
			headers.replace ("x-apple-baa-time", device["x-apple-baa-time"]);
			headers.replace ("x-apple-baa-version", device["x-apple-baa-version"]);

			Bytes response = yield send_raw (message, cancellable);
			try {
				PlistDict result = new Plist.from_data (response.get_data ()).get_dict ("Response");
				PlistDict status = result.get_dict ("Status");
				if (status.get_integer ("ec") != 0)
					throw new Efni.Error.PROTOCOL ("Grand Slam rejected the request: %s",
						status.has ("em") ? status.get_string ("em") : status.get_integer ("ec").to_string ());
				return result;
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed Grand Slam response: %s", e.message);
			}
		}

		private async Bytes send_raw (Soup.Message message, Cancellable? cancellable) throws Efni.Error, IOError {
			try {
				Bytes response = yield session.send_and_read_async (message, Priority.DEFAULT, cancellable);
				if (message.status_code != 200)
					throw new Efni.Error.PROTOCOL ("Grand Slam returned HTTP %u", message.status_code);
				return response;
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to reach Grand Slam: %s", e.message);
			}
		}

		private PlistDict build_cpd (Gee.Map<string, string> device) {
			string lduid = device["X-Apple-I-LDUID"];
			string sdid = device["X-Apple-I-SDID"];
			string stable_id = device["X-Apple-I-Stable-ID"];

			var cpd = new PlistDict ();
			cpd.set_string ("X-Apple-I-Client-Time", current_timestamp ());
			cpd.set_string ("X-Apple-I-Device-Configuration-Mode", "0");
			cpd.set_string ("X-Apple-I-Flow-Id", Uuid.string_random ().up ());
			cpd.set_string ("X-Apple-I-LDUID", lduid);
			cpd.set_string ("X-Apple-I-MD", device["X-Apple-I-MD"]);
			cpd.set_string ("X-Apple-I-MD-EUID", device["X-Apple-I-MD-EUID"]);
			cpd.set_string ("X-Apple-I-MD-LU", device["X-Apple-I-MD-LU"]);
			cpd.set_string ("X-Apple-I-MD-M", device["X-Apple-I-MD-M"]);
			cpd.set_string ("X-Apple-I-MD-RINFO", device["X-Apple-I-MD-RINFO"]);
			cpd.set_string ("X-Apple-I-MLB", device["X-Apple-I-MLB"]);
			cpd.set_string ("X-Apple-I-ROM", device["X-Apple-I-ROM"]);
			cpd.set_string ("X-Apple-I-Request-UUID", Uuid.string_random ().up ());
			cpd.set_string ("X-Apple-I-SDID", sdid);
			cpd.set_string ("X-Apple-I-SRL-NO", device["X-Apple-I-SRL-NO"]);
			cpd.set_string ("X-Apple-I-Stable-ID", stable_id);
			cpd.set_boolean ("X-Apple-Offer-Security-Upgrade", true);
			cpd.set_string ("X-Apple-Requested-Partition", "0");
			cpd.set_string ("X-Apple-Security-Upgrade-Context", "com.apple.authkit.generic");
			cpd.set_string ("X-Mme-Device-Id", device["X-Mme-Device-Id"]);
			cpd.set_integer ("at", 2);
			cpd.set_boolean ("bootstrap", true);
			cpd.set_string ("capp", "FaceTime");
			cpd.set_string ("cbid", "com.apple.FaceTime");
			cpd.set_boolean ("ckgen", true);
			cpd.set_string ("cou", "NO");
			cpd.set_string ("dc", "9");
			cpd.set_string ("dec", "unknown");
			cpd.set_boolean ("fcd", true);
			cpd.set_boolean ("generatePrk", true);
			cpd.set_boolean ("icdrsDisabled", false);
			cpd.set_boolean ("icscrec", true);
			cpd.set_string ("lduid", lduid);
			cpd.set_string ("loc", "en_US@rg=nozzzz");
			cpd.set_boolean ("pbe", false);
			cpd.set_boolean ("prkgen", true);
			cpd.set_string ("ptkn", device["ptkn"]);
			cpd.set_string ("sdid", sdid);
			cpd.set_string ("stableId", stable_id);
			cpd.set_string ("svct", "facetime");
			cpd.set_boolean ("webAccessEnabled", false);
			cpd.set_string ("x-apple-baa-cert", device["x-apple-baa-cert"]);
			cpd.set_string ("x-apple-baa-sig", device["x-apple-baa-sig"]);
			cpd.set_string ("x-apple-baa-sig-alt", device["x-apple-baa-sig-alt"]);
			cpd.set_string ("x-apple-baa-time", device["x-apple-baa-time"]);
			cpd.set_string ("x-apple-baa-version", device["x-apple-baa-version"]);
			cpd.set_string ("x-apple-i-device-type", device["x-apple-i-device-type"]);
			return cpd;
		}

		private static uint8[] pbkdf2_sha256 (uint8[] secret, uint8[] salt, int iterations, int length) {
			var block = new uint8[salt.length + 4];
			Memory.copy (block, salt, salt.length);
			block[salt.length + 3] = 1;

			uint8[] u = hmac_sha256 (secret, block);
			var result = u[0:length];
			for (int i = 1; i != iterations; i++) {
				u = hmac_sha256 (secret, u);
				for (int j = 0; j != length; j++)
					result[j] ^= u[j];
			}
			return result;
		}

		private static uint8[] hmac_sha256 (uint8[] key, uint8[] data) {
			var mac = new Hmac (ChecksumType.SHA256, key);
			mac.update (data);
			var digest = new uint8[32];
			size_t length = digest.length;
			mac.get_digest (digest, ref length);
			return digest;
		}

		private static uint8[] hash (Bytes[] parts) {
			var checksum = new Checksum (ChecksumType.SHA256);
			foreach (unowned Bytes part in parts)
				checksum.update (part.get_data (), part.get_size ());
			var digest = new uint8[32];
			size_t length = digest.length;
			checksum.get_digest (digest, ref length);
			return digest;
		}

		private static uint8[] aes_256_cbc_decrypt (uint8[] key, uint8[] iv, uint8[] ciphertext) throws Efni.Error {
			var cipher = OpenSSL.Envelope.Cipher.fetch (null, "AES-256-CBC");
			var ctx = new OpenSSL.Envelope.CipherContext ();
			if (ctx.decrypt_init (cipher, key, iv) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to initialize AES");

			var output = new uint8[ciphertext.length + 16];
			int produced = 0;
			ctx.decrypt_update (output, ref produced, ciphertext);
			int total = produced;
			ctx.decrypt_final ((uint8[]) ((uint8 *) output + total), ref produced);
			total += produced;
			return output[0:total];
		}

		private static OpenSSL.BigNumber bn_from (uint8[] data) {
			return new OpenSSL.BigNumber.from_big_endian (data);
		}

		private static uint8[] bn_to_padded (OpenSSL.BigNumber value) {
			var buffer = new uint8[256];
			value.to_big_endian_padded (buffer);
			return buffer;
		}

		private static uint8[] bn_to_bytes (OpenSSL.BigNumber value) {
			int n = value.num_bytes ();
			if (n == 0)
				return new uint8[0];
			var buffer = new uint8[n];
			value.to_big_endian (buffer);
			return buffer;
		}

		private static uint8[] decode_hex (string hex) {
			var result = new uint8[hex.length / 2];
			for (int i = 0; i != result.length; i++)
				result[i] = (uint8) uint64.parse (hex.substring (i * 2, 2), 16);
			return result;
		}

		private static string bin_to_hex (uint8[] data) {
			var builder = new StringBuilder ();
			foreach (uint8 b in data)
				builder.append_printf ("%02x", b);
			return builder.str;
		}

		private static bool constant_time_equal (uint8[] a, uint8[] b) {
			if (a.length != b.length)
				return false;
			uint8 diff = 0;
			for (int i = 0; i != a.length; i++)
				diff |= a[i] ^ b[i];
			return diff == 0;
		}

		private Soup.Session session = new Soup.Session ();
		private AppleTrust trust = new AppleTrust ();
	}

	/**
	 * A successful Grand Slam sign-in: the directory identifiers and the PET that
	 * authorizes IDS delegate login.
	 */
	public sealed class GrandSlamIdentity : Object {
		public string adsid {
			get;
			construct;
		}

		public string dsid {
			get;
			construct;
		}

		public string pet {
			get;
			construct;
		}

		public int64 pet_expiry {
			get;
			construct;
		}

		public GrandSlamIdentity (string adsid, string dsid, string pet, int64 pet_expiry) {
			Object (adsid: adsid, dsid: dsid, pet: pet, pet_expiry: pet_expiry);
		}
	}

	/**
	 * Supplies the security code shown on a trusted device when Grand Slam demands
	 * two-factor authentication.
	 */
	public interface TwoFactorProvider : Object {
		public abstract async string request_security_code (Cancellable? cancellable) throws Efni.Error, IOError;
	}
}
