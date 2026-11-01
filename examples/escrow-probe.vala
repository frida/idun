namespace Idun.Examples {
	private static int main (string[] args) {
		if (args.length < 3) {
			printerr ("Usage: %s <oracle-base-url> <apple-id>\n", args[0]);
			printerr ("The Apple ID password is read from the IDUN_APPLE_PASSWORD environment variable.\n");
			return 1;
		}

		var loop = new MainLoop ();
		int exit_code = 0;
		probe.begin (args[1], args[2], (obj, res) => {
			exit_code = probe.end (res);
			loop.quit ();
		});
		loop.run ();
		return exit_code;
	}

	private async int probe (string base_url, string apple_id) {
		try {
			string? password = Environment.get_variable ("IDUN_APPLE_PASSWORD");
			if (password == null) {
				printerr ("Set IDUN_APPLE_PASSWORD before running.\n");
				return 1;
			}

			var oracle = new IdentityOracle (base_url);
			print ("[probe] activating APNs...\n"); stdout.flush ();
			ApnsIdentity push = yield new ApnsActivation (oracle, new ApnsIdentityStore ()).activate ();
			print ("[probe] APNs activated; opening courier...\n"); stdout.flush ();
			var courier = new ApnsCourier (push, new ApnsTokenStore ());
			yield courier.open ();
			print ("[probe] courier open\n"); stdout.flush ();

			string? cache_path = Environment.get_variable ("IDUN_ESCROW_CACHE");
			string? record_id = Environment.get_variable ("IDUN_ESCROW_RECORD_ID");
			bool want_icloud = Environment.get_variable ("IDUN_ESCROW_TOKEN_KIND") == "icloud";

			Gee.Map<string, string> anisette = yield oracle.fetch_anisette ();
			string device_id = anisette.has_key ("X-Mme-Device-Id") ? anisette["X-Mme-Device-Id"] : "";
			string client_info = Environment.get_variable ("IDUN_ESCROW_CLIENT_INFO") ?? "";

			string escrow_proxy_url, escrow_token;
			string pet_tok = "", icloud_tok = "", appleid_tok = "";
			if (cache_path != null && FileUtils.test (cache_path, FileTest.EXISTS)) {
				uint8[] cached; FileUtils.get_data (cache_path, out cached);
				var cache = new Plist.from_data (cached);
				escrow_proxy_url = cache.get_string ("escrowProxyUrl");
				escrow_token = want_icloud ? cache.get_string ("icloudAuthToken") : cache.get_string ("pet");
				print ("loaded escrow creds from cache\n");
			} else {
				var grand_slam = new GrandSlam (oracle);
				print ("[probe] GSA authenticate (client=%s)...\n",
					Environment.get_variable ("IDUN_GSA_CLIENT") ?? "facetime"); stdout.flush ();
				GrandSlamIdentity account = yield grand_slam.authenticate (apple_id, password,
					courier.push_token, new ConsoleTwoFactor ());
				print ("[probe] GSA done; pet len=%d; IDS delegate...\n", account.pet.length); stdout.flush ();
				pet_tok = account.pet;
				icloud_tok = account.icloud_auth_token;
				appleid_tok = account.appleid_auth_token;
				IdsDelegate delegation = yield new IdsDelegateAuth (oracle).authenticate (apple_id, account);
				print ("[probe] IDS delegate done; escrow url=%s\n", delegation.cloud_kit.escrow_proxy_url); stdout.flush ();
				escrow_proxy_url = delegation.cloud_kit.escrow_proxy_url;
				string kind = Environment.get_variable ("IDUN_ESCROW_TOKEN_KIND") ?? "pet";
				escrow_token = (kind == "icloud") ? account.icloud_auth_token
					: (kind == "appleid") ? account.appleid_auth_token : account.pet;
				if (cache_path != null) {
					var cache = new Plist ();
					cache.set_string ("escrowProxyUrl", escrow_proxy_url);
					cache.set_string ("pet", account.pet);
					cache.set_string ("icloudAuthToken", account.icloud_auth_token);
					FileUtils.set_data (cache_path, cache.to_binary ());
				}
			}

			if (Environment.get_variable ("IDUN_ESCROW_TRY_ALL") != null) {
				string[] names = { "pet", "icloud", "appleid", "icloud+PET", "appleid+PET", "pet+PET" };
				string[] toks = { pet_tok, icloud_tok, appleid_tok,
					icloud_tok + "PET", appleid_tok + "PET", pet_tok + "PET" };
				for (int i = 0; i != names.length; i++) {
					print ("[try] kind=%s len=%d tail=%s\n", names[i], toks[i].length,
						toks[i].substring (int.max (0, toks[i].length - 8)));
					var c = new EscrowProxyClient (escrow_proxy_url, apple_id, toks[i]);
					if (device_id != "") c.device_id = device_id;
					if (client_info != "") c.client_info = client_info;
					try { print ("[try] %s get_records OK: %s\n", names[i], (yield c.get_records ()).get_string ("message")); }
					catch (GLib.Error err) { print ("[try] %s FAILED: %s\n", names[i], err.message.split ("\n")[0]); }
				}
				return 0;
			}

			var client = new EscrowProxyClient (escrow_proxy_url, apple_id, escrow_token);
			if (device_id != "") client.device_id = device_id;
			if (client_info != "") client.client_info = client_info;
			add_anisette (client, anisette);
			print ("escrow %s token len %d device-id %s\n", escrow_proxy_url, escrow_token.length, device_id);
			print ("[pet-full] %s\n", escrow_token);

			if (Environment.get_variable ("IDUN_ESCROW_CLUB") != null) {
				try { print ("get_club_cert:\n%s\n", (yield client.get_club_cert ()).to_xml ()); }
				catch (GLib.Error e) { print ("get_club_cert failed: %s\n", e.message); }
			}
			try {
				var records = yield client.get_records ();
				print ("get_records OK: %s\n", records.get_string ("message"));
				if (Environment.get_variable ("IDUN_ESCROW_DUMP_RECORDS") != null)
					print ("%s\n", records.to_xml ());
			}
			catch (GLib.Error e) { print ("get_records failed: %s\n", e.message); }
			if (record_id != null) {
				try { print ("srp_init:\n%s\n", (yield client.srp_init (record_id)).to_xml ()); }
				catch (GLib.Error e) { print ("srp_init failed: %s\n", e.message); }
			}
		} catch (GLib.Error e) {
			printerr ("error: %s\n", e.message);
			return 1;
		}
		return 0;
	}

	private static void add_anisette (EscrowProxyClient client, Gee.Map<string, string> anisette) {
		foreach (var key in new string[] { "X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO" }) {
			if (anisette.has_key (key))
				client.anisette_headers[key] = anisette[key];
		}
	}

	private sealed class ConsoleTwoFactor : Object, TwoFactorProvider {
		public async string request_security_code (Cancellable? cancellable) throws Efni.Error, IOError {
			string? env = Environment.get_variable ("IDUN_2FA_CODE");
			if (env != null)
				return env.replace (" ", "").strip ();

			string path = Environment.get_variable ("IDUN_2FA_FILE") ?? "/tmp/idun-2fa";
			FileUtils.remove (path);
			print ("[2fa] login started; waiting for a code at %s (push should reach your trusted device now)\n", path);
			for (int i = 0; i != 300; i++) {
				if (FileUtils.test (path, FileTest.EXISTS)) {
					string contents;
					FileUtils.get_contents (path, out contents);
					string code = contents.replace (" ", "").replace ("\n", "").strip ();
					if (code.length >= 6) {
						FileUtils.remove (path);
						print ("[2fa] got code\n");
						return code;
					}
				}
				Timeout.add_seconds (1, request_security_code.callback);
				yield;
			}
			throw new Efni.Error.NOT_SUPPORTED ("Timed out waiting for two-factor code");
		}
	}
}
