using Efni;

namespace Idun {
	public sealed class CoreDeviceInfoService : TrustedService {
		public static async CoreDeviceInfoService open (Device device, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var channel = yield device.open_tcp_channel ("com.apple.coredevice.deviceinfo", ALLOW_TUNNEL, cancellable);
			var service = new CoreDeviceInfoService (channel.stream);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private CoreDeviceInfoService (IOStream stream) {
			Object (stream: stream);
		}

		public async Gee.List<DisplayInfo> query_displays (Cancellable? cancellable = null) throws Efni.Error, IOError {
			var response = yield invoke ("com.apple.coredevice.feature.getdisplayinfo", null, cancellable);

			var displays = new Gee.ArrayList<DisplayInfo> ();
			response.read_member ("displays");
			uint n = response.count_elements ();
			for (uint i = 0; i != n; i++) {
				response.read_element (i);

				var display = new DisplayInfo ();
				display.primary = response.read_member ("primary").get_bool_value ();
				response.end_member ();
				response.read_member ("currentMode").read_member ("size");
				display.width = (uint) response.read_element (0).get_double_value ();
				response.end_element ();
				display.height = (uint) response.read_element (1).get_double_value ();
				response.end_element ();
				response.end_member ().end_member ();
				displays.add (display);

				response.end_element ();
			}
			return displays;
		}
	}

	public sealed class DisplayInfo : Object {
		public bool primary {
			get;
			set;
		}

		public uint width {
			get;
			set;
		}

		public uint height {
			get;
			set;
		}
	}
}
