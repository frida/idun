namespace Idun.Examples {
	private static int main (string[] args) {
		if (args.length < 2) {
			printerr ("Usage: %s screenshot <path> | pasteboard get|set <text>|watch | displays | stream | tap <x> <y> | home\n", args[0]);
			return 1;
		}

		var demo = new CoreDeviceDemo (args[1:]);
		return demo.run ();
	}

	private class CoreDeviceDemo : Object {
		private string[] command;
		private MainLoop loop = new MainLoop ();
		private DeviceMonitor monitor = new DeviceMonitor ();
		private Cancellable cancellable = new Cancellable ();
		private int exit_code = 0;

		public CoreDeviceDemo (string[] command) {
			this.command = command;
		}

		public int run () {
			Unix.signal_add (Posix.Signal.INT, () => {
				cancellable.cancel ();
				return Source.REMOVE;
			});

#if HAVE_DAEMON
			string? idund = Environment.get_variable ("IDUND");
			if (idund != null)
				monitor.set_daemon_locator (() => idund);
#endif

			monitor.device_attached.connect (on_device_attached);
			monitor.start.begin (cancellable, on_monitor_started);

			loop.run ();

			return exit_code;
		}

		private void on_monitor_started (Object? source, AsyncResult result) {
			try {
				monitor.start.end (result);
			} catch (GLib.Error e) {
				fail (e);
			}
		}

		private void on_device_attached (Device device) {
			monitor.device_attached.disconnect (on_device_attached);
			perform_command.begin (device);
		}

		private async void perform_command (Device device) {
			try {
				switch (command[0]) {
					case "screenshot":
						yield capture_screenshot (device, command[1]);
						break;
					case "pasteboard":
						yield use_pasteboard (device, command[1:]);
						break;
					case "displays":
						yield list_displays (device);
						break;
					case "stream":
						yield stream_display (device);
						break;
					case "tap":
						yield tap (device, double.parse (command[1]), double.parse (command[2]));
						break;
					case "home":
						yield go_home (device);
						break;
					default:
						throw new Efni.Error.INVALID_ARGUMENT ("Unknown command: %s", command[0]);
				}
			} catch (GLib.Error e) {
				fail (e);
				return;
			}

			finish ();
		}

		private async void capture_screenshot (Device device, string path) throws GLib.Error {
			var service = yield ScreenCaptureService.open (device, cancellable);
			Bytes png = yield service.capture_screenshot (cancellable);
			service.close ();

			FileUtils.set_data (path, png.get_data ());
			print ("Wrote %zu bytes to %s\n", png.get_size (), path);
		}

		private async void use_pasteboard (Device device, string[] args) throws GLib.Error {
			var service = yield PasteboardService.open (device, cancellable);

			switch (args[0]) {
				case "get": {
					PasteboardSnapshot snapshot = yield service.pull (cancellable);
					print_snapshot (snapshot);
					break;
				}
				case "set":
					yield service.set_text (args[1], cancellable);
					break;
				case "watch":
					service.changed.connect (print_snapshot);
					yield service.enable_notifications (cancellable);
					print ("Watching pasteboard, press Ctrl+C to stop\n");
					yield wait_for_cancellation ();
					break;
			}

			service.close ();
		}

		private static void print_snapshot (PasteboardSnapshot snapshot) {
			print ("change_count=%" + int64.FORMAT_MODIFIER + "d items=%d text=%s\n",
				snapshot.change_count, snapshot.items.size, snapshot.text ?? "(none)");
			foreach (PasteboardItem item in snapshot.items) {
				foreach (var representation in item.representations.entries)
					print ("\t%s: %zu bytes\n", representation.key, representation.value.get_size ());
			}
		}

		private async void list_displays (Device device) throws GLib.Error {
			var service = yield CoreDeviceInfoService.open (device, cancellable);
			Gee.List<DisplayInfo> displays = yield service.query_displays (cancellable);
			foreach (DisplayInfo display in displays)
				print ("%ux%u%s\n", display.width, display.height, display.primary ? " (primary)" : "");
			service.close ();
		}

		private async void stream_display (Device device) throws GLib.Error {
			var stream = yield DisplayStream.open (device, cancellable);
			print ("Streaming %ux%u at %u fps, payload type %u, clock rate %u, local SSRC %u, remote SSRC %u\n",
				stream.width, stream.height, stream.framerate, stream.payload_type, stream.clock_rate,
				stream.local_ssrc, stream.remote_ssrc);

			uint packets = 0;
			uint64 bytes = 0;
			stream.rtp.connect (data => {
				packets++;
				bytes += data.get_size ();
			});
			stream.rtcp.connect (data => {
				packets++;
				bytes += data.get_size ();
			});

			yield wait_for_cancellation ();

			print ("Received %u packets totalling %" + uint64.FORMAT_MODIFIER + "u bytes\n", packets, bytes);

			yield stream.close ();
		}

		private async void tap (Device device, double x, double y) throws GLib.Error {
			var hid = yield HidClient.open (device, cancellable);
			hid.touch_down (x, y);
			hid.touch_up (x, y);
			yield settle ();
			hid.close ();
		}

		private async void go_home (Device device) throws GLib.Error {
			var hid = yield HidClient.open (device, cancellable);
			yield hid.perform_home_gesture (cancellable);
			yield settle ();
			hid.close ();
		}

		private async void settle () {
			var source = new TimeoutSource (500);
			source.set_callback (settle.callback);
			source.attach (MainContext.get_thread_default ());
			yield;
		}

		private async void wait_for_cancellation () {
			var source = new CancellableSource (cancellable);
			source.set_callback (wait_for_cancellation.callback);
			source.attach (MainContext.get_thread_default ());
			yield;
		}

		private void fail (GLib.Error e) {
			printerr ("%s\n", e.message);
			exit_code = 1;
			finish ();
		}

		private void finish () {
			monitor.stop.begin (null, () => loop.quit ());
		}
	}
}
