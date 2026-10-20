using Efni;

namespace Idun {
	public sealed class ScreenCaptureService : TrustedService {
		public static async ScreenCaptureService open (Device device, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var channel = yield device.open_tcp_channel ("com.apple.coredevice.screencaptureservice", ALLOW_TUNNEL, cancellable);
			var service = new ScreenCaptureService (channel.stream);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private ScreenCaptureService (IOStream stream) {
			Object (stream: stream);
		}

		public async Bytes capture_screenshot (Cancellable? cancellable = null) throws Efni.Error, IOError {
			Bytes input = new XpcObjectBuilder ()
				.begin_dictionary ()
					.set_member_name ("requestedFormat")
					.add_string_value ("png")
				.end_dictionary ()
				.build ();
			var response = yield invoke ("com.apple.coredevice.feature.capturescreenshot", input, cancellable);

			return response.read_member ("image").get_data_value ();
		}
	}
}
