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
			ApnsIdentity push = yield new ApnsActivation (oracle, new ApnsIdentityStore ()).activate ();
			var courier = new ApnsCourier (push, new ApnsTokenStore ());
			yield courier.open ();

			string? cache_path = Environment.get_variable ("IDUN_CK_CACHE");
			CloudKitCredentials credentials;
			if (cache_path != null && FileUtils.test (cache_path, FileTest.EXISTS)) {
				uint8[] cached; FileUtils.get_data (cache_path, out cached);
				var cache = new Plist.from_data (cached);
				credentials = new CloudKitCredentials (cache.get_string ("cloudKitToken"), "", "",
					cache.get_string ("ckCode"), cache.get_string ("ckDevice"), "", cache.get_string ("dsid"));
				print ("loaded cached CloudKit credentials from %s\n", cache_path);
			} else {
				var grand_slam = new GrandSlam (oracle);
				GrandSlamIdentity account = yield grand_slam.authenticate (apple_id, password,
					courier.push_token, new ConsoleTwoFactor ());
				IdsDelegate delegation = yield new IdsDelegateAuth (oracle).authenticate (apple_id, account);
				credentials = delegation.cloud_kit;
				if (cache_path != null) {
					var cache = new Plist ();
					cache.set_string ("cloudKitToken", credentials.cloud_kit_token);
					cache.set_string ("ckCode", credentials.ck_code_gateway_url);
					cache.set_string ("ckDevice", credentials.ck_device_gateway_url);
					cache.set_string ("dsid", credentials.dsid);
					FileUtils.set_data (cache_path, cache.to_binary ());
					print ("saved CloudKit credentials to %s\n", cache_path);
				}
			}

			DeviceIdentity device = yield oracle.fetch_device_info ();
			Gee.Map<string, string> anisette = yield oracle.fetch_anisette ();

			print ("cloud-kit token: %s\n", credentials.cloud_kit_token);
			print ("gateway: %s\n", credentials.ck_code_gateway_url);
			print ("dsid: %s\n", credentials.dsid);

			var client = new CloudKitClient (credentials);
			client.device_identifier = Uuid.string_random ().up ();
			client.stable_identifier = Uuid.string_random ().up ();
			client.device_info = device;
			client.extra_headers = anisette;
			print ("attached %u anisette headers\n", anisette.size);
			string? tts = Environment.get_variable ("IDUN_TT_SCHEME");
			if (tts != null) client.trusted_target_scheme = int.parse (tts);
			string? ot = Environment.get_variable ("IDUN_OP_TYPE");
			if (ot != null) client.operation_type = int.parse (ot);
			if (Environment.get_variable ("IDUN_NO_USERID") != null) client.omit_user_id = true;
			string? scoped_override = Environment.get_variable ("IDUN_CK_SCOPED_USER_ID");
			if (scoped_override != null) client.scoped_user_id = scoped_override;
			print ("device-service: %s\n", credentials.ck_device_gateway_url);
			if (Environment.get_variable ("IDUN_CK_NO_BOOTSTRAP") == null) {
				print ("bootstrapping CloudKit device session...\n");
				string scoped = yield client.bootstrap (courier.push_token);
				print ("scoped user id: %s\n", scoped);
			}
			print ("user-id: %s\n", client.user_id ());
			print ("device-identifier: %s\n", client.device_identifier);
			string function_name = Environment.get_variable ("IDUN_CF_FUNCTION") ?? "fetchViableBottles";
			string? params_hex = Environment.get_variable ("IDUN_CF_PARAMS");
			Bytes parameters = (params_hex != null)
				? new Bytes (from_hex (params_hex))
				: new Bytes (fetch_viable_bottles_params ());
			Bytes response = new Bytes ({});
			if (function_name != "surveyZones" && function_name != "dumpZone") {
				print ("invoking Cuttlefish/%s (params %u bytes)...\n", function_name, parameters.length);
				response = yield client.invoke (function_name, parameters);
				print ("response: %u bytes\n", response.length);
				print_hex (response.get_data ());
			}

			if (function_name == "dumpZone") {
				string zone = Environment.get_variable ("IDUN_ZONE") ?? "SecureObjectSync";
				string? want_type = Environment.get_variable ("IDUN_RECORD_TYPE");
				uint8[] zid = CkksZone.record_zone_identifier (zone, client.user_id ());
				uint8[]? cont = null;
				do {
					Bytes page_bytes = yield client.fetch_zone_records (
						CkksZone.build_retrieve_changes_request (zid, cont));
					var page = CkksZone.parse_page (page_bytes.get_data ());
					foreach (var r in page.records) {
						if (want_type != null && r.record_type != want_type)
							continue;
						var sb = new StringBuilder ();
						foreach (var fn in r.field_names ())
							sb.append (fn + ",");
						print ("REC %s type=%s fields=%s\n", r.record_name, r.record_type, sb.str);
					}
					cont = page.has_more ? page.continuation.get_data () : null;
				} while (cont != null);
				return 0;
			}

			if (function_name == "surveyZones") {
				foreach (string zone in CkksZone.KEYCHAIN_ZONES) {
					uint8[] zid = CkksZone.record_zone_identifier (zone, client.user_id ());
					try {
						Bytes page_bytes = yield client.fetch_zone_records (
							CkksZone.build_retrieve_changes_request (zid, null));
						var page = CkksZone.parse_page (page_bytes.get_data ());
						var counts = new Gee.HashMap<string, int> ();
						foreach (var r in page.records)
							counts[r.record_type] = (counts.has_key (r.record_type) ? counts[r.record_type] : 0) + 1;
						var sb = new StringBuilder ();
						foreach (var e in counts.entries)
							sb.append_printf ("%s=%d ", e.key, e.value);
						print ("zone %-22s %3u records  %s%s\n", zone, page.records.size, sb.str,
							page.has_more ? "(more)" : "");
					} catch (GLib.Error e) {
						print ("zone %-22s ERROR %s\n", zone, e.message);
					}
				}
				return 0;
			}

			if (function_name == "fetchChanges") {
				var changes = OctagonTrustChanges.parse (response.get_data ());
				print ("trust graph: %u peers; sync token %s\n", changes.peers.size,
					changes.sync_token);
				var policy = changes.current_policy ();
				if (policy != null) {
					print ("current policy: frozen v%" + uint64.FORMAT + " %s / flexible v%"
						+ uint64.FORMAT + " %s\n", policy.frozen_version, policy.frozen_hash,
						policy.flexible_version, policy.flexible_hash);
				}
				string? sponsor = Environment.get_variable ("IDUN_SPONSOR_PEER_ID");
				if (sponsor != null && policy != null) {
					Gee.List<string> included;
					uint64 stable_clock, dynamic_clock;
					changes.compute_trust (sponsor, out included, out stable_clock,
						out dynamic_clock);
					var sponsor_peer = changes.peer_for_id (sponsor);
					uint64 ucv = 2;
					string os = "macOS 27.0.0 (26A428)";
					if (sponsor_peer != null && sponsor_peer.stable_info != null) {
						var si = OctagonStableInfo.parse (sponsor_peer.stable_info.info.get_data ());
						ucv = si.user_controllable_views;
						os = si.os_version;
					}
					var self = OctagonSelfPeer.generate (policy, device.serial_number,
						device.hardware_version, device.serial_number, os, stable_clock,
						dynamic_clock, included, ucv);
					print ("built self-peer %s (stable clock %" + uint64.FORMAT
						+ ", dynamic clock %" + uint64.FORMAT + ", trusts %u)\n", self.peer_id,
						stable_clock, dynamic_clock, included.size);
					// Self-verify the signatures we just produced, round-tripping through the parser.
					var parsed = OctagonTrustChanges.parse (new ProtobufWriter ().append_bytes (1,
						new ProtobufWriter ().append_bytes (2, new ProtobufWriter ()
							.append_bytes (3, self.encode_for_join (
								new OctagonVoucher (new Bytes ({ 0x01 }), new Bytes ({ 0x02 })))).data)
						.data).data);
					var pr = parsed.peers[0];
					bool ok = OctagonPeerKeys.verify_prefixed (self.signing_spki ().get_data (),
						pr.stable_info.info.get_data (), pr.stable_info.signature.get_data (),
						OctagonPeerKeys.STABLE_INFO_SIG_TYPE);
					print ("  self-peer stable-info signature verifies: %s\n", ok ? "yes" : "no");
				}
			}

			if (function_name == "fetchRecoverableTLKShares") {
				var shares = OctagonEscrowRecovery.parse_recoverable_tlk_shares (response.get_data ());
				print ("parsed %u recoverable TLK share(s):\n", shares.size);
				foreach (var share in shares) {
					uint8[] ephemeral, ciphertext, auth_code;
					share.decode_wrapped_key (out ephemeral, out ciphertext, out auth_code);
					print ("  %s\n    recv=%s eph=%d ct=%d tag=%d\n", share.record_name,
						share.receiver_peer_id, ephemeral.length, ciphertext.length, auth_code.length);
				}
			}

			if (function_name == "fetchViableBottles") {
				var bottles = OctagonEscrowRecovery.parse_viable_bottles (response.get_data ());
				print ("parsed %u viable bottle(s):\n", bottles.size);
				foreach (var vb in bottles) {
					var bottle = OctagonBottle.parse (vb.bottle.get_data ());
					print ("  label=%s\n    peer=%s bottleID=%s\n", vb.record_label,
						bottle.peer_id, bottle.bottle_id);
				}
			}
		} catch (GLib.Error e) {
			printerr ("error: %s\n", e.message);
			return 1;
		}
		return 0;
	}

	private uint8[] fetch_viable_bottles_params () {
		var context = new ProtobufWriter ()
			.append_bytes (1, ("idun-flowID-" + Uuid.string_random ().up ()).data)
			.append_bytes (2, ("idun-deviceSessionID-" + Uuid.string_random ().up ()).data)
			.data;
		return new ProtobufWriter ()
			.append_varint (1, 1)
			.append_bytes (2, context)
			.data;
	}

	private uint8[] from_hex (string hex) {
		var bytes = new uint8[hex.length / 2];
		for (int i = 0; i != bytes.length; i++)
			bytes[i] = (uint8) (hex.substring (i * 2, 2).to_long (null, 16));
		return bytes;
	}

	private void print_hex (uint8[] data) {
		var sb = new StringBuilder ();
		for (int i = 0; i != int.min (data.length, 256); i++)
			sb.append_printf ("%02x", data[i]);
		print ("%s\n", sb.str);
	}

	private sealed class ConsoleTwoFactor : Object, TwoFactorProvider {
		public async string request_security_code (Cancellable? cancellable) throws Efni.Error, IOError {
			print ("Enter the two-factor code: ");
			string? code = stdin.read_line ();
			if (code == null)
				throw new Efni.Error.NOT_SUPPORTED ("No two-factor code supplied");
			return code.strip ();
		}
	}
}
