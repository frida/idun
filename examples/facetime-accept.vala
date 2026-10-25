namespace Idun.Examples {
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
			var ngm = NgmIdentity.load_or_generate (new NgmIdentityStore ());
			RegisteredService registration = yield new IdsRegistration (oracle).register (identity, push,
				courier.push_token, message, handle, ngm);
			print ("registered %s with NGM identity; waiting for a call\n", registration.handle);

			var endpoint = new FaceTimeEndpoint (courier, crypto, handle);
			yield endpoint.listen ();

			endpoint.notification_received.connect ((notification) => {
				inspect (notification);
			});
			yield endpoint.run ();
		} catch (GLib.Error e) {
			printerr ("error: %s\n", e.message);
			return 1;
		}
		return 0;
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
