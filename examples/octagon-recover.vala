namespace Idun.Examples {
	private static int main (string[] args) {
		if (args.length < 3) {
			printerr ("Usage: %s <oracle-base-url> <apple-id>\n", args[0]);
			return 1;
		}
		var loop = new MainLoop ();
		int code = 0;
		run.begin (args[1], args[2], (o, r) => { code = run.end (r); loop.quit (); });
		loop.run ();
		return code;
	}

	private async int run (string base_url, string apple_id) {
		try {
			string? password = Environment.get_variable ("IDUN_APPLE_PASSWORD");
			string? icsc = Environment.get_variable ("IDUN_ICSC");
			string target = Environment.get_variable ("IDUN_TARGET_PEER");
			string altdsid = Environment.get_variable ("IDUN_ALTDSID") ?? "";
			string entropy_path = Environment.get_variable ("IDUN_ENTROPY_OUT")
				?? "/tmp/idun-bottle-entropy.bin";

			var oracle = new IdentityOracle (base_url);
			ApnsIdentity push = yield new ApnsActivation (oracle, new ApnsIdentityStore ()).activate ();
			var courier = new ApnsCourier (push, new ApnsTokenStore ());
			yield courier.open ();

			string ck_cache = Environment.get_variable ("IDUN_CK_CACHE") ?? "";

			DeviceIdentity device = yield oracle.fetch_device_info ();
			Gee.Map<string, string> anisette = yield oracle.fetch_anisette ();

			CloudKitCredentials creds;
			EscrowProxyClient? escrow = null;
			if (ck_cache != "" && FileUtils.test (ck_cache, FileTest.EXISTS)) {
				uint8[] cached;
				FileUtils.get_data (ck_cache, out cached);
				var store = new Plist.from_data (cached);
				creds = new CloudKitCredentials (store.get_string ("ckToken"),
					store.get_string ("ktToken"), store.get_string ("mmeToken"),
					store.get_string ("ckCode"), store.get_string ("ckDevice"),
					store.get_string ("escrowUrl"), store.get_string ("dsid"));
				print ("loaded cached CloudKit credentials\n");
			} else {
				var grand_slam = new GrandSlam (oracle);
				GrandSlamIdentity account = yield grand_slam.authenticate (apple_id, password,
					courier.push_token, new FileTwoFactor ());
				IdsDelegate delegation = yield new IdsDelegateAuth (oracle).authenticate (apple_id,
					account);
				creds = delegation.cloud_kit;

				escrow = new EscrowProxyClient (creds.escrow_proxy_url, apple_id, account.pet);
				if (anisette.has_key ("X-Mme-Device-Id"))
					escrow.device_id = anisette["X-Mme-Device-Id"];
				foreach (var key in new string[] { "X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO" }) {
					if (anisette.has_key (key))
						escrow.anisette_headers[key] = anisette[key];
				}

				if (ck_cache != "") {
					var store = new Plist ();
					store.set_string ("ckToken", creds.cloud_kit_token);
					store.set_string ("ktToken", creds.key_transparency_token);
					store.set_string ("mmeToken", creds.mme_auth_token);
					store.set_string ("ckCode", creds.ck_code_gateway_url);
					store.set_string ("ckDevice", creds.ck_device_gateway_url);
					store.set_string ("escrowUrl", creds.escrow_proxy_url);
					store.set_string ("dsid", creds.dsid);
					FileUtils.set_data (ck_cache, store.to_binary ());
				}
			}

			var cuttlefish = new CloudKitClient (creds);
			cuttlefish.device_identifier = Uuid.string_random ().up ();
			cuttlefish.stable_identifier = Uuid.string_random ().up ();
			cuttlefish.device_info = device;
			cuttlefish.extra_headers = anisette;
			yield cuttlefish.bootstrap (courier.push_token);

			var recovery = new OctagonEscrowRecovery (escrow, cuttlefish);
			OctagonViableBottle bottle = yield select_bottle (recovery, target);
			print ("target bottle: %s\n", bottle.record_label);

			Bytes entropy = yield obtain_entropy (escrow, bottle, icsc, entropy_path);
			if (entropy == null)
				return 0;

			var contents = OctagonBottle.recover_identity (bottle.bottle.get_data (),
				entropy.get_data (), altdsid);
			uint8[] encryption_key = contents.peer_encryption_key.key_data.get_data ();
			print ("recovered peer keys\n");

			var tlks = yield recover_tlks (recovery, target, encryption_key);
			print ("recovered %u TLK(s)\n", tlks.size);

			yield recover_account_kt_key (cuttlefish, tlks);
		} catch (GLib.Error e) {
			printerr ("error: %s\n", e.message);
			return 1;
		}
		return 0;
	}

	private async OctagonViableBottle select_bottle (OctagonEscrowRecovery recovery, string target)
			throws GLib.Error {
		foreach (var bottle in yield recovery.fetch_viable_bottles ()) {
			if (OctagonBottle.parse (bottle.bottle.get_data ()).peer_id == target)
				return bottle;
		}
		throw new Efni.Error.NOT_SUPPORTED ("No viable bottle for target peer %s", target);
	}

	private async Bytes? obtain_entropy (EscrowProxyClient? escrow, OctagonViableBottle bottle,
			string? icsc, string entropy_path) throws GLib.Error {
		if (FileUtils.test (entropy_path, FileTest.EXISTS)) {
			uint8[] saved;
			FileUtils.get_data (entropy_path, out saved);
			print ("loaded saved entropy (%d bytes)\n", saved.length);
			return new Bytes (saved);
		}
		if (escrow == null) {
			print ("no saved entropy and no escrow session (cached-creds run)\n");
			return null;
		}
		if (Environment.get_variable ("IDUN_CONFIRM") != "yes") {
			print ("dry run (set IDUN_CONFIRM=yes to spend an escrow attempt)\n");
			return null;
		}
		print ("recovering (IRREVERSIBLE)...\n"); stdout.flush ();
		Bytes entropy = yield escrow.recover (bottle.record_label, icsc.data, true);
		FileUtils.set_data (entropy_path, entropy.get_data ());
		print ("entropy recovered and saved (%u bytes)\n", entropy.length);
		return entropy;
	}

	private async Gee.Map<string, Bytes> recover_tlks (OctagonEscrowRecovery recovery, string target,
			uint8[] encryption_key) throws GLib.Error {
		var tlks = new Gee.HashMap<string, Bytes> ();
		foreach (var share in yield recovery.fetch_recoverable_tlk_shares (target)) {
			if (share.receiver_peer_id != target)
				continue;
			try {
				string uuid;
				Bytes key;
				share.unwrap (encryption_key, out uuid, out key);
				tlks[uuid] = key;
			} catch (GLib.Error e) {
			}
		}
		return tlks;
	}

	private async void recover_account_kt_key (CloudKitClient cuttlefish, Gee.Map<string, Bytes> tlks)
			throws GLib.Error {
		var service_keys = new Gee.HashMap<string, Bytes> ();
		DecryptedKeychainItem? kt_item = null;
		foreach (string zone in CkksZone.KEYCHAIN_ZONES) {
			foreach (var item in CkksKeychain.decrypt_zone (yield fetch_zone (cuttlefish, zone), tlks)) {
				string agrp = string_attr (item.attributes, "agrp");
				string labl = string_attr (item.attributes, "labl");
				if (agrp.has_prefix ("com.apple.ProtectedCloudStorage")) {
					try {
						uint8[] v_data = item.attributes.get_bytes ("v_Data").get_data ();
						if (v_data[0] != 0x30)
							continue;
						uint8[] scalar = PcsKey.parse_private_scalar (v_data);
						uint8[] point = PcsKey.public_point (scalar);
						service_keys[sha1_hex (point)] = new Bytes (scalar);
						service_keys[hex (new Bytes (point[1 : 33]))] = new Bytes (scalar);
					} catch (GLib.Error e) {
					}
				}
				if (labl.has_prefix ("PCS com.apple.KTAccountKey")
						&& string_attr (item.attributes, "acct")
							== Environment.get_variable ("IDUN_KT_ACCT"))
					kt_item = item;
			}
			stdout.flush ();
		}
		print ("PCS service keys: %u\n", service_keys.size);
		if (kt_item == null) {
			print ("KTAccountKey item not found\n");
			return;
		}

		uint8[] envelope = kt_item.attributes.get_bytes ("v_Data").get_data ();
		uint8[] ephemeral, wrapped, master_id;
		parse_pcs_envelope (envelope, out ephemeral, out wrapped, out master_id);

		string master = hex (new Bytes (master_id));
		string own = hex (kt_item.record.bytes_field ("pcspublickey"));
		print ("service keys indexed: %u; master=%s own=%s\n", service_keys.size, master, own);

		string? recipient = service_keys.has_key (master) ? master
			: (service_keys.has_key (own) ? own : null);
		if (recipient == null) {
			print ("no PCS service key matches master or own id\n");
			return;
		}
		print ("recipient service key: %s\n", recipient);

		uint8[] unwrapped = PcsKey.rfc6637_unwrap (service_keys[recipient].get_data (), ephemeral,
			wrapped);
		print ("unwrapped account KT key material (%d bytes): %s\n", unwrapped.length,
			hex (new Bytes (unwrapped)));

		var kt = new KtAccountKey (new Bytes (account_kt_x963 (unwrapped)));
		print ("accountKTKeyId = %s (expect 2fcb57a86b4a3b185cb029024e0b820ffff7a3b5)\n",
			hex (kt.account_key_id ()));
	}

	// The sealed PCS envelope: APP5{ OCTET{ protobuf f1{ f1 = keyId(32)||ephemeralX(32), f2=pub },
	// f2{ f1 = wrapped blob } } }.
	private void parse_pcs_envelope (uint8[] envelope, out uint8[] ephemeral, out uint8[] wrapped,
			out uint8[] master_id) throws GLib.Error {
		uint8[] octet = envelope[8 : envelope.length];

		uint8[] f1 = protobuf_bytes (octet, 1);
		uint8[] f2 = protobuf_bytes (octet, 2);

		uint8[] key_and_ephemeral = protobuf_bytes (f1, 1);
		ephemeral = key_and_ephemeral[32 : 64];

		wrapped = protobuf_bytes (f2, 1);

		uint8[] wrapper = protobuf_bytes (f1, 2);
		master_id = extract_master_id (wrapper);
	}

	private uint8[] extract_master_id (uint8[] wrapper) throws GLib.Error {
		for (int i = 0; i + 25 <= wrapper.length; i++) {
			if (wrapper[i] == 0x04 && wrapper[i + 1] == 0x14 && wrapper[i + 22] == 0x02
					&& wrapper[i + 23] == 0x01 && wrapper[i + 24] == 0x01)
				return wrapper[i + 2 : i + 22];
		}
		throw new Efni.Error.PROTOCOL ("master key id not found in PCS wrapper");
	}

	private string sha1_hex (uint8[] data) {
		var checksum = new Checksum (ChecksumType.SHA1);
		checksum.update (data, data.length);
		return checksum.get_string ();
	}

	private uint8[] protobuf_bytes (uint8[] data, int field) throws GLib.Error {
		var reader = new ProtobufReader (data);
		while (reader.has_more) {
			uint8 wire_type;
			if (reader.read_field (out wire_type) == field && wire_type == 2)
				return reader.read_bytes ();
			reader.skip (wire_type);
		}
		throw new Efni.Error.PROTOCOL ("field %d not found", field);
	}

	// The account KT key in X9.63 (04||X||Y||D) from the unwrapped compact form (X||d or d).
	private uint8[] account_kt_x963 (uint8[] unwrapped) throws GLib.Error {
		uint8[] scalar = (unwrapped.length == 64) ? unwrapped[32 : 64]
			: (unwrapped.length == 32) ? unwrapped : unwrapped[unwrapped.length - 32 : unwrapped.length];
		uint8[] point = PcsKey.public_point (scalar);
		uint8[] result = new uint8[point.length + 32];
		Memory.copy (result, point, point.length);
		Memory.copy ((uint8 *) result + point.length, scalar, 32);
		return result;
	}

	private string string_attr (Plist attributes, string key) {
		try {
			return attributes.get_string (key);
		} catch (GLib.Error e) {
			return "";
		}
	}

	private string hex (Bytes bytes) {
		var sb = new StringBuilder ();
		foreach (uint8 b in bytes.get_data ())
			sb.append_printf ("%02x", b);
		return sb.str;
	}

	private async Gee.List<CloudKitRecord> fetch_zone (CloudKitClient cuttlefish, string zone)
			throws GLib.Error {
		var records = new Gee.ArrayList<CloudKitRecord> ();
		uint8[] zone_id = CkksZone.record_zone_identifier (zone, cuttlefish.user_id ());
		uint8[] continuation = null;
		do {
			Bytes page_bytes = yield cuttlefish.fetch_zone_records (
				CkksZone.build_retrieve_changes_request (zone_id, continuation));
			var page = CkksZone.parse_page (page_bytes.get_data ());
			records.add_all (page.records);
			continuation = page.has_more ? page.continuation.get_data () : null;
		} while (continuation != null);
		return records;
	}

	private sealed class FileTwoFactor : Object, TwoFactorProvider {
		public async string request_security_code (Cancellable? cancellable) throws Efni.Error, IOError {
			string path = Environment.get_variable ("IDUN_2FA_FILE") ?? "/tmp/idun-2fa";
			FileUtils.remove (path);
			print ("[2fa] waiting for a code at %s\n", path); stdout.flush ();
			for (int i = 0; i != 300; i++) {
				if (FileUtils.test (path, FileTest.EXISTS)) {
					string contents;
					FileUtils.get_contents (path, out contents);
					string code = contents.replace (" ", "").replace ("\n", "").strip ();
					if (code.length >= 6) {
						FileUtils.remove (path);
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
