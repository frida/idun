namespace Idun.Examples {
	private static int main (string[] args) {
		if (args.length < 2) {
			printerr ("Usage: %s screenshot <path> | pasteboard get|set <text>|watch | displays | stream | tap <x> <y> | home | services | notify <name|post:name>... | launch <bundle-id> [url] | invoke <service> <feature> [json]\n", args[0]);
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
					case "services":
						yield list_services (device);
						break;
					case "notify":
						yield observe_notifications (device, command[1:]);
						break;
					case "launch":
						yield launch_app (device, command[1], (command.length > 2) ? command[2] : null);
						break;
					case "invoke":
						yield invoke_feature (device, command[1], command[2], (command.length > 3) ? command[3] : null);
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

			yield stream.start (cancellable);
			print ("Streaming %ux%u at %u fps, payload type %u, clock rate %u, local SSRC %u, remote SSRC %u\n",
				stream.width, stream.height, stream.framerate, stream.payload_type, stream.clock_rate,
				stream.local_ssrc, stream.remote_ssrc);

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

		private async void list_services (Device device) throws GLib.Error {
			var tunnel = yield device.find_tunnel (cancellable);
			if (tunnel == null)
				throw new Efni.Error.NOT_SUPPORTED ("No tunnel");
			foreach (ServiceInfo service in tunnel.discovery.query_services ()) {
				print ("%s (port %u)\n", service.name, service.port);
				foreach (string feature in service.features)
					print ("\t%s\n", feature);
			}
		}

		private async void observe_notifications (Device device, string[] names) throws GLib.Error {
			var proxy = yield NotificationProxyClient.open (device, cancellable);
			proxy.notification.connect (name => print ("%s\n", name));
			foreach (unowned string name in names) {
				if (name.has_prefix ("post:"))
					proxy.post (name[5:]);
				else
					proxy.observe (name);
			}
			print ("Observing, press Ctrl+C to stop\n");
			yield wait_for_cancellation ();
			yield proxy.close ();
		}

		private async void launch_app (Device device, string bundle_id, string? url) throws GLib.Error {
			var channel = yield device.open_tcp_channel ("com.apple.coredevice.appservice", ALLOW_TUNNEL, cancellable);
			var service = yield AppService.open (channel.stream, cancellable);
			var options = new AppService.LaunchOptions ();
			options.payload_url = url;
			AppService.ProcessInfo process = yield service.launch_application (bundle_id, options, cancellable);
			print ("Launched pid %u: %s\n", process.pid, process.path);
			service.close ();
		}

		private async void invoke_feature (Device device, string service_name, string feature, string? json) throws GLib.Error {
			var channel = yield device.open_tcp_channel (service_name, ALLOW_TUNNEL, cancellable);
			var service = yield RawService.open (channel.stream, cancellable);
			Bytes? input = null;
			if (json != null) {
				var builder = new XpcObjectBuilder ();
				json_to_xpc (Json.from_string (json), builder);
				input = builder.build ();
			}
			Variant result = yield service.call (feature, input, cancellable);
			print ("%s\n", result.print (true));
			service.close ();
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

	private class RawService : TrustedService {
		public static async RawService open (IOStream stream, Cancellable? cancellable) throws GLib.Error {
			var service = new RawService (stream);
			yield service.init_async (Priority.DEFAULT, cancellable);
			return service;
		}

		private RawService (IOStream stream) {
			Object (stream: stream);
		}

		public async Variant call (string feature, Bytes? input, Cancellable? cancellable) throws GLib.Error {
			var reader = yield invoke (feature, input, cancellable);
			return reader.current_object;
		}
	}

	private void json_to_xpc (Json.Node node, Efni.ObjectBuilder builder) throws GLib.Error {
		switch (node.get_node_type ()) {
			case OBJECT: {
				builder.begin_dictionary ();
				var obj = node.get_object ();
				foreach (string name in obj.get_members ()) {
					if (name.has_prefix ("@data:")) {
						builder.set_member_name (name[6:]);
						builder.add_data_value (new Bytes (Base64.decode (obj.get_string_member (name))));
					} else if (name.has_prefix ("@uuid:")) {
						builder.set_member_name (name[6:]);
						string hex = obj.get_string_member (name).replace ("-", "");
						var bytes = new uint8[16];
						for (int i = 0; i != 16; i++)
							bytes[i] = (uint8) uint.parse (hex.substring (2 * i, 2), 16);
						builder.add_uuid_value (bytes);
					} else if (name.has_prefix ("@u64:")) {
						builder.set_member_name (name[5:]);
						builder.add_uint64_value ((uint64) obj.get_int_member (name));
					} else {
						builder.set_member_name (name);
						json_to_xpc (obj.get_member (name), builder);
					}
				}
				builder.end_dictionary ();
				break;
			}
			case ARRAY: {
				builder.begin_array ();
				foreach (Json.Node element in node.get_array ().get_elements ())
					json_to_xpc (element, builder);
				builder.end_array ();
				break;
			}
			case VALUE: {
				Type t = node.get_value_type ();
				if (t == typeof (string))
					builder.add_string_value (node.get_string ());
				else if (t == typeof (bool))
					builder.add_bool_value (node.get_boolean ());
				else if (t == typeof (int64))
					builder.add_int64_value (node.get_int ());
				else if (t == typeof (double))
					builder.add_double_value (node.get_double ());
				else
					throw new Efni.Error.INVALID_ARGUMENT ("Unsupported JSON value type");
				break;
			}
			case NULL:
				builder.add_null_value ();
				break;
		}
	}
}
