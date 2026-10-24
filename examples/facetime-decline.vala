namespace Idun.Examples {
	private static int main (string[] args) {
		if (args.length < 4) {
			printerr ("Usage: %s <oracle-base-url> <apple-id> <handle>\n", args[0]);
			printerr ("The Apple ID password is read from the IDUN_APPLE_PASSWORD environment variable.\n");
			return 1;
		}

		var loop = new MainLoop ();
		int exit_code = 0;
		decline_incoming_calls.begin (args[1], args[2], args[3], (obj, res) => {
			exit_code = decline_incoming_calls.end (res);
			loop.quit ();
		});
		loop.run ();
		return exit_code;
	}

	private async int decline_incoming_calls (string base_url, string apple_id, string handle) {
		try {
			var oracle = new IdentityOracle (base_url);

			string? password = Environment.get_variable ("IDUN_APPLE_PASSWORD");
			if (password == null) {
				printerr ("Set IDUN_APPLE_PASSWORD before running.\n");
				return 1;
			}

			var grand_slam = new GrandSlam (oracle);
			GrandSlamIdentity account = yield grand_slam.authenticate (apple_id, password, new ConsoleTwoFactor ());
			print ("signed in: %s\n", account.adsid);

			IdsDelegate delegation = yield new IdsDelegateAuth (oracle).authenticate (apple_id, account);
			IdsIdentity identity = yield new IdsAuthCert (oracle).authenticate (delegation);
			print ("ids identity: profile %s\n", identity.profile_id);

			ApnsIdentity push = yield new ApnsActivation (oracle, new ApnsIdentityStore ()).activate ();
			var courier = new ApnsCourier (push, new ApnsTokenStore ());
			yield courier.open ();
			print ("courier token: %u bytes\n", courier.push_token.length);

			var message = MessageIdentity.load_or_generate (new MessageIdentityStore ());
			RegisteredService registration = yield new IdsRegistration (oracle).register (identity, push,
				courier.push_token, message, handle);
			print ("registered %s as a FaceTime endpoint\n", registration.handle);

			var lookup = new IdsLookup (oracle);
			var endpoint = new FaceTimeEndpoint (courier, new PairCrypto (message), handle);
			yield endpoint.listen ();
			print ("listening for calls; they will be declined automatically\n");

			endpoint.notification_received.connect ((notification) => {
				answer_with_decline.begin (endpoint, lookup, identity, registration, courier, notification);
			});
			yield endpoint.run ();
		} catch (GLib.Error e) {
			printerr ("error: %s\n", e.message);
			return 1;
		}
		return 0;
	}

	private async void answer_with_decline (FaceTimeEndpoint endpoint, IdsLookup lookup, IdsIdentity identity,
			RegisteredService registration, ApnsCourier courier, Variant notification) {
		try {
			Variant? payload = notification.lookup_value ("payload", new VariantType ("a{sv}"));
			if (payload == null)
				return;
			Variant? caller = payload.lookup_value ("sP", VariantType.STRING);
			if (caller == null)
				return;

			Gee.MultiMap<string, PeerIdentity> peers = yield lookup.query (identity, registration.certificate,
				courier.push_token, endpoint.handle, { caller.get_string () });
			Gee.Collection<PeerIdentity> senders = peers[caller.get_string ()];
			if (senders.is_empty)
				return;

			CallInvitation invitation = endpoint.open_invitation (notification, senders);
			yield endpoint.decline (invitation);
			print ("declined call %s from %s\n", invitation.group_id, invitation.caller_uri);
		} catch (GLib.Error e) {
			printerr ("ignoring notification: %s\n", e.message);
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
