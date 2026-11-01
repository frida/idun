namespace Idun.Examples {
	private static int main (string[] args) {
		if (args.length < 3) {
			printerr ("Usage: %s <oracle-base-url> <handle>\n", args[0]);
			return 1;
		}

		var loop = new MainLoop ();
		int exit_code = 0;
		capture_incoming_calls.begin (args[1], args[2], (obj, res) => {
			exit_code = capture_incoming_calls.end (res);
			loop.quit ();
		});
		loop.run ();
		return exit_code;
	}

	private async int capture_incoming_calls (string base_url, string handle) {
		try {
			var oracle = new IdentityOracle (base_url);

			ApnsIdentity push = yield new ApnsActivation (oracle, new ApnsIdentityStore ()).activate ();
			var courier = new ApnsCourier (push, new ApnsTokenStore ());
			yield courier.open ();
			print ("courier open; token %u bytes\n", courier.push_token.length);

			var message = MessageIdentity.load_or_generate (new MessageIdentityStore ());
			var endpoint = new FaceTimeEndpoint (courier, new PairCrypto (message), handle);
			yield endpoint.listen ();
			print ("listening as %s; call it now\n", handle);

			int n = 0;
			endpoint.notification_received.connect ((notification) => {
				n++;
				print ("\n===== message %d =====\n%s\n", n, notification.print (true));
			});
			yield endpoint.run ();
		} catch (GLib.Error e) {
			printerr ("error: %s\n", e.message);
			return 1;
		}
		return 0;
	}
}
