namespace Idun.Examples {
	private static int main (string[] args) {
		if (args.length < 2) {
			printerr ("Usage: %s <oracle-base-url>\n", args[0]);
			return 1;
		}

		var loop = new MainLoop ();
		int exit_code = 0;
		run.begin (args[1], (obj, res) => {
			exit_code = run.end (res);
			loop.quit ();
		});
		loop.run ();
		return exit_code;
	}

	private async int run (string base_url) {
		try {
			var oracle = new IdentityOracle (base_url);

			DeviceIdentity device = yield oracle.fetch_device_info ();
			print ("device: %s %s\n", device.hardware_version, device.serial_number);
			print ("push user-agent: %s\n", device.push_user_agent);

			var activation = new ApnsActivation (oracle, new ApnsIdentityStore ());
			ApnsIdentity identity = yield activation.activate ();
			print ("push certificate: %u bytes\n", identity.push_certificate.length);

			ValidationData validation = yield oracle.produce_validation_data ();
			print ("validation data: %u bytes, valid until %s\n", validation.data.length, validation.valid_until);
		} catch (GLib.Error e) {
			printerr ("error: %s\n", e.message);
			return 1;
		}
		return 0;
	}
}
