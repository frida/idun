namespace Idun.Examples {
	private static Bytes? device_signing_key;

	private static int main (string[] args) {
		if (args.length < 4) {
			printerr ("Usage: %s <oracle-base-url> <apple-id> <handle>\n", args[0]);
			printerr ("The Apple ID password is read from the IDUN_APPLE_PASSWORD environment variable.\n");
			return 1;
		}

		var loop = new MainLoop ();
		int exit_code = 0;
		accept_incoming_calls.begin (args[1], args[2], args[3], (obj, res) => {
			exit_code = accept_incoming_calls.end (res);
			loop.quit ();
		});
		loop.run ();
		return exit_code;
	}

	private async int accept_incoming_calls (string base_url, string apple_id, string handle) {
		try {
			var oracle = new IdentityOracle (base_url);

			ApnsIdentity push = yield new ApnsActivation (oracle, new ApnsIdentityStore ()).activate ();
			var courier = new ApnsCourier (push, new ApnsTokenStore ());
			yield courier.open ();

			var ids_store = new IdsIdentityStore ();
			IdsIdentity? identity = ids_store.load ();
			if (identity == null) {
				string? password = Environment.get_variable ("IDUN_APPLE_PASSWORD");
				if (password == null) {
					printerr ("Set IDUN_APPLE_PASSWORD before running.\n");
					return 1;
				}

				var grand_slam = new GrandSlam (oracle);
				GrandSlamIdentity account = yield grand_slam.authenticate (apple_id, password,
					courier.push_token, new ConsoleTwoFactor ());
				IdsDelegate delegation = yield new IdsDelegateAuth (oracle).authenticate (apple_id, account);
				identity = yield new IdsAuthCert (oracle).authenticate (delegation);
				ids_store.save (identity);
				print ("authenticated with Apple and cached the IDS identity\n");
			} else {
				print ("reusing the persisted IDS identity\n");
			}

			var message = MessageIdentity.load_or_generate (new MessageIdentityStore ());
			var crypto = new PairCrypto (message);
			NgmIdentity? ngm = (Environment.get_variable ("IDUN_NO_NGM") != null)
				? null
				: NgmIdentity.load_or_generate (new NgmIdentityStore ());
			if (ngm != null)
				device_signing_key = ngm.signing_key;
			RegisteredService? registration = null;
			try {
				registration = yield new IdsRegistration (oracle).register (identity, push,
					courier.push_token, message, handle, ngm);
				print ("registered %s with NGM identity; waiting for a call\n", registration.handle);
			} catch (Efni.Error e) {
				if (Environment.get_variable ("IDUN_TOLERATE_REGISTER") != null)
					print ("register failed (%s); listening on the existing registration\n", e.message);
				else
					throw e;
			}

			var endpoint = new FaceTimeEndpoint (courier, crypto, handle);
			yield endpoint.listen ();

			var lookup = new IdsLookup (oracle);
			endpoint.notification_received.connect ((notification) => {
				inspect (notification);
				if (is_pair_tetra (notification) && registration != null && ngm != null) {
					decrypt_invitation.begin (endpoint, lookup, identity, registration, courier.push_token,
						ngm, handle, notification);
				}
			});
			yield endpoint.run ();
		} catch (GLib.Error e) {
			printerr ("error: %s\n", e.message);
			return 1;
		}
		return 0;
	}

	private bool is_pair_tetra (Variant notification) {
		Variant? payload = notification.lookup_value ("payload", new VariantType ("a{sv}"));
		if (payload == null)
			return false;
		Variant? envelope = payload.lookup_value ("E", VariantType.STRING);
		return envelope != null && envelope.get_string () == "pair-tetra";
	}

	private async void decrypt_invitation (FaceTimeEndpoint endpoint, IdsLookup lookup,
			IdsIdentity identity, RegisteredService registration, Bytes push_token, NgmIdentity ngm,
			string self_handle, Variant notification) {
		try {
			Variant payload = notification.lookup_value ("payload", new VariantType ("a{sv}"));
			Variant? sender = payload.lookup_value ("sP", VariantType.STRING);
			if (sender == null)
				return;
			string sender_uri = sender.get_string ();

			Gee.MultiMap<string, PeerIdentity> peers = yield lookup.query (identity,
				registration.certificate, push_token, self_handle, { sender_uri });
			Gee.Collection<PeerIdentity> senders = peers[sender_uri];
			if (senders.is_empty) {
				print ("  could not resolve sender %s for decryption\n", sender_uri);
				return;
			}

			FaceTimeCall? call;
			bool verified = true;
			try {
				call = endpoint.open_tetra_invitation (notification, senders, ngm);
			} catch (Efni.Error e) {
				print ("  signature unverified (%s); decrypting without verification\n", e.message);
				verified = false;
				call = endpoint.open_tetra_invitation (notification, senders, ngm, false);
			}
			if (call == null) {
				print ("  in-call session update (not an incoming call); not answering\n");
				return;
			}
			uint8[] plaintext = call.invitation.get_data ();
			bool bplist = plaintext.length >= 8 &&
				(string) plaintext[0 : 8] == "bplist00";
			print ("  *** DECRYPTED pair-tetra invitation: %d bytes%s (signature %s) ***\n",
				plaintext.length, bplist ? " (bplist00)" : "", verified ? "verified" : "UNVERIFIED");
			string path = "research/facetime/captures/ft-plaintext-%08x.bin".printf ((uint) get_real_time ());
			try {
				FileUtils.set_data (path, plaintext);
				print ("  wrote plaintext to %s\n", path);
			} catch (FileError e) {
			}

			yield call.accept ();
			print ("  sent call answer (media announcement for group %s)\n", call.group_id);
		} catch (GLib.Error e) {
			print ("  pair-tetra decrypt failed: %s\n", e.message);
		}
	}

	private void inspect (Variant notification) {
		Variant? payload = notification.lookup_value ("payload", new VariantType ("a{sv}"));
		if (payload == null)
			return;
		Variant? type = payload.lookup_value ("c", VariantType.INT64);
		Variant? envelope = payload.lookup_value ("E", VariantType.STRING);
		Variant? sender = payload.lookup_value ("sP", VariantType.STRING);
		print ("notification c=%" + int64.FORMAT_MODIFIER + "d E=%s sP=%s\n",
			type != null ? type.get_int64 () : -1,
			envelope != null ? envelope.get_string () : "(none)",
			sender != null ? sender.get_string () : "(none)");

		if (envelope != null && envelope.get_string () == "pair-tetra")
			dump_pair_tetra (payload);

		Variant? relay_ip = payload.lookup_value ("qrip", new VariantType ("ay"));
		if (relay_ip != null) {
			Variant? relay_port = payload.lookup_value ("qrp", VariantType.INT64);
			Variant? relay_participant = payload.lookup_value ("qri", VariantType.INT64);
			uint8[] ip = relay_ip.get_data_as_bytes ().get_data ();
			print ("  *** QuickRelay allocation: relay %u.%u.%u.%u:%" + int64.FORMAT_MODIFIER
				+ "d participant=%" + int64.FORMAT_MODIFIER + "d ***\n",
				ip[0], ip[1], ip[2], ip[3],
				relay_port != null ? relay_port.get_int64 () : -1,
				relay_participant != null ? relay_participant.get_int64 () : -1);
			string session_id = format_uuid (payload.lookup_value ("qids", new VariantType ("ay")).get_data_as_bytes ().get_data ());
			connect_relay.begin (ip, (uint16) relay_port.get_int64 (),
				payload.lookup_value ("qrst", new VariantType ("ay")).get_data_as_bytes (),
				payload.lookup_value ("qrsk", new VariantType ("ay")).get_data_as_bytes (),
				session_id);
		}
	}

	private async void connect_relay (uint8[] ip, uint16 port, Bytes session_token, Bytes session_key,
			string session_id) {
		try {
			var salt = new uint8[12];
			OpenSSL.Rng.generate (salt);
			uint8[] psk = FaceTimeQuickRelay.derive_quic_psk (session_key, salt);
			uint8[] identity = FaceTimeQuickRelay.build_quic_psk_identity (salt, session_token);

			var relay = new InetSocketAddress (new InetAddress.from_bytes (ip, SocketFamily.IPV4), port);

			print ("  connecting QUIC to relay...\n");
			var conn = yield FaceTimeRelayConnection.open (relay, new Bytes (identity), new Bytes (psk));
			print ("  *** QuickRelay QUIC+PSK handshake OK ***\n");

			var prekey = FaceTimeEndpoint.generate_media_key ();
			var prekey_material = FaceTimeQuickRelay.build_prekey_material (session_id, device_signing_key,
				FaceTimeEndpoint.media_public_point (prekey));

			var skm = new uint8[32];
			var sks = new uint8[16];
			var ski = new uint8[16];
			OpenSSL.Rng.generate (skm);
			OpenSSL.Rng.generate (sks);
			OpenSSL.Rng.generate (ski);
			uint8[] avc_data = FaceTimeEndpoint.build_avc_container (format_uuid (session_participant_uuid ()),
				Random.next_int (), ntp_time (), Random.next_int ());
			var avcblob_material = FaceTimeQuickRelay.build_avcblob_material (session_id, skm, sks, ski, avc_data);

			uint8[] body = FaceTimeRelayProtocol.build_allocbind (quic_pod_id (0), quic_pod_id (1),
				new FaceTimeMaterial[] { prekey_material, avcblob_material });
			Bytes resp = yield conn.request ("PUT", "AllocBind", body);
			print ("  *** AllocBind response: %zu bytes: %s ***\n", resp.get_size (),
				format_head (resp.get_data ()));
		} catch (GLib.Error e) {
			print ("  QuickRelay request failed: %s\n", e.message);
		}
	}

	private uint8[] session_participant_uuid () {
		var uuid = new uint8[16];
		OpenSSL.Rng.generate (uuid);
		return uuid;
	}

	private uint64 ntp_time () {
		return ((uint64) (get_real_time () / 1000000 + 2208988800)) << 32;
	}

	private uint8[] quic_pod_id (uint32 type) {
		uint32 item = (Random.next_int () & 0x0fffffff) | (type << 28) | 0x800000;
		return { (uint8) (item >> 24), (uint8) (item >> 16), (uint8) (item >> 8), (uint8) item };
	}

	private string format_uuid (uint8[] b) {
		return "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X".printf (
			b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
			b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
	}

	private string format_head (uint8[] data) {
		var sb = new StringBuilder ();
		for (int i = 0; i != int.min (data.length, 32); i++)
			sb.append_printf ("%02x", data[i]);
		return sb.str;
	}

	private void dump_pair_tetra (Variant payload) {
		Variant? sealed = payload.lookup_value ("P", new VariantType ("ay"));
		if (sealed == null)
			return;
		try {
			var dir = File.new_for_path ("research/facetime/captures");
			dir.make_directory_with_parents ();
		} catch (GLib.Error e) {
		}
		string path = "research/facetime/captures/ft-%08x.bin".printf ((uint) get_real_time ());
		try {
			FileUtils.set_data (path, sealed.get_data_as_bytes ().get_data ());
			print ("captured pair-tetra message to %s\n", path);
			var message = TetraMessage.unwrap (sealed.get_data_as_bytes ().get_data ());
			print ("  index=%" + uint64.FORMAT_MODIFIER + "u encap=%s used_registered_keys=%s\n",
				message.message_index,
				message.kem_encapsulation != null ? "%u bytes".printf (message.kem_encapsulation.length) : "(none)",
				message.used_registered_keys != null ? "%u bytes".printf (message.used_registered_keys.length) : "(none)");
		} catch (GLib.Error e) {
			print ("  capture/parse failed: %s\n", e.message);
		}
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
