namespace Idun.Examples {
	private static int main (string[] args) {
		if (args.length < 4) {
			printerr ("Usage: %s <oracle-base-url> <self-handle> <lookup-handle>\n", args[0]);
			return 1;
		}

		var loop = new MainLoop ();
		int exit_code = 0;
		probe.begin (args[1], args[2], args[3], (obj, res) => {
			exit_code = probe.end (res);
			loop.quit ();
		});
		loop.run ();
		return exit_code;
	}

	private async int probe (string base_url, string self_handle, string lookup_handle) {
		try {
			var oracle = new IdentityOracle (base_url);

			ApnsIdentity push = yield new ApnsActivation (oracle, new ApnsIdentityStore ()).activate ();
			var courier = new ApnsCourier (push, new ApnsTokenStore ());
			yield courier.open ();

			var ids_store = new IdsIdentityStore ();
			IdsIdentity? identity = ids_store.load ();
			if (identity == null) {
				printerr ("no persisted IDS identity; run facetime-accept first\n");
				return 1;
			}

			var message = MessageIdentity.load_or_generate (new MessageIdentityStore ());
			var ngm = NgmIdentity.load_or_generate (new NgmIdentityStore ());
			RegisteredService registration = yield new IdsRegistration (oracle).register (identity, push,
				courier.push_token, message, self_handle, ngm);

			print ("our push token: %s\n", hex (courier.push_token));

			var lookup = new IdsLookup (oracle);
			Gee.MultiMap<string, PeerIdentity> peers = yield lookup.query (identity,
				registration.certificate, courier.push_token, self_handle, { lookup_handle });
			Gee.Collection<PeerIdentity> devices = peers[lookup_handle];
			print ("lookup of %s returned %d device(s)\n", lookup_handle, devices.size);
			int i = 0;
			foreach (PeerIdentity device in devices) {
				bool self = device.push_token.compare (courier.push_token) == 0;
				string signing = device.ngm_prekey != null
					? hex (device.ngm_prekey.signing_point)
					: "none";
				print ("  [%d] token=%s signing=%s%s\n", i++, hex (device.push_token), signing,
					self ? "  <= THIS IS IDUN" : "");
			}
		} catch (GLib.Error e) {
			printerr ("error: %s\n", e.message);
			return 1;
		}
		return 0;
	}

	private string hex (Bytes bytes) {
		var sb = new StringBuilder ();
		foreach (uint8 b in bytes.get_data ())
			sb.append_printf ("%02x", b);
		return sb.str;
	}
}
