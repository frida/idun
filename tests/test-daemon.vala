using Efni;

namespace Idun.DaemonTest {
	public void add_tests () {
		GLib.Test.add_func ("/Daemon/client-connects-and-enumerates", () => {
			var h = new Harness ((h) => client_connects_and_enumerates.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Daemon/unknown-device-is-rejected", () => {
			var h = new Harness ((h) => unknown_device_is_rejected.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Daemon/monitor-spawns-daemon", () => {
			var h = new Harness ((h) => monitor_spawns_daemon.begin (h as Harness));
			h.run ();
		});
	}

	private async void client_connects_and_enumerates (Harness h) {
		var fixture = yield Fixture.create ();
		try {
			var client = yield DaemonClient.open_endpoint (fixture.server.client_address, null);

			assert_true (client.service.protocol_version == Daemon.PROTOCOL_VERSION);
			assert_false (client.service.autospawned);

			var devices = yield client.service.enumerate_devices (null, null);
			foreach (var description in devices)
				assert_nonnull (description["udid"]);

			yield client.close (null);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			yield fixture.destroy ();
		}

		h.done ();
	}

	private async void unknown_device_is_rejected (Harness h) {
		var fixture = yield Fixture.create ();
		try {
			var client = yield DaemonClient.open_endpoint (fixture.server.client_address, null);

			try {
				yield client.service.open_tunnel ("00000000-0000000000000000", null, null);
				assert_not_reached ();
			} catch (GLib.Error e) {
				try {
					Daemon.throw_remote_error (e);
				} catch (Efni.Error translated) {
					assert_true (translated is Efni.Error.INVALID_ARGUMENT);
				} catch (IOError translated) {
					assert_not_reached ();
				}
			}

			yield client.close (null);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			yield fixture.destroy ();
		}

		h.done ();
	}

	private async void monitor_spawns_daemon (Harness h) {
		string daemon_path = Environment.get_variable ("IDUN_TEST_IDUND");
		try {
			var monitor = new DeviceMonitor ();
			monitor.set_daemon_locator (() => daemon_path);
			yield monitor.start (null);
			yield monitor.stop (null);

			var client = yield DaemonClient.open_shared (() => daemon_path, null);
			assert_true (client.service.autospawned);
			yield client.service.shutdown (null, null);
			yield client.close (null);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		}

		h.done ();
	}

	private class Fixture {
		public DaemonServer server;
		private string directory;

		public static async Fixture create () {
			var fixture = new Fixture ();
			try {
				fixture.directory = DirUtils.make_tmp ("idun-test-XXXXXX");
				fixture.server = new DaemonServer (Path.build_filename (fixture.directory, "control"), false, 0, false);
				yield fixture.server.start (null);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n", e.message);
				assert_not_reached ();
			}
			return fixture;
		}

		public async void destroy () {
			try {
				yield server.stop (null);
			} catch (IOError e) {
			}
			DirUtils.remove (directory);
		}
	}

	private class Harness : Test.AsyncHarness {
		public Harness (owned Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
		}
	}
}
