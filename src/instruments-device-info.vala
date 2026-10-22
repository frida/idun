using Efni;

namespace Idun {
	public sealed class DeviceInfoService : Object, AsyncInitable {
		public ChannelProvider channel_provider {
			get;
			construct;
		}

		private DTXChannel channel;

		private DeviceInfoService (ChannelProvider channel_provider) {
			Object (channel_provider: channel_provider);
		}

		public static async DeviceInfoService open (ChannelProvider channel_provider, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			var service = new DeviceInfoService (channel_provider);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Efni.Error, IOError {
			var connection = yield DTXConnection.obtain (channel_provider, cancellable);

			channel = connection.make_channel ("com.apple.instruments.server.services.deviceinfo");

			return true;
		}

		public async Gee.List<ProcessInfo> enumerate_processes (Cancellable? cancellable = null) throws Efni.Error, IOError {
			var result = new Gee.ArrayList<ProcessInfo> ();

			var response = yield channel.invoke ("runningProcesses", null, cancellable);

			NSArray? processes = response as NSArray;
			if (processes == null)
				throw new Efni.Error.PROTOCOL ("Malformed response");

			foreach (var element in processes.elements) {
				NSDictionary? process = element as NSDictionary;
				if (process == null)
					throw new Efni.Error.PROTOCOL ("Malformed response");

				var info = new ProcessInfo ();

				info.pid = (uint) process.get_value<NSNumber> ("pid").integer;

				info.name = process.get_value<NSString> ("name").str;
				info.real_app_name = resolve_real_app_name (process.get_value<NSString> ("realAppName").str);
				info.is_application = process.get_value<NSNumber> ("isApplication").boolean;

				NSNumber? foreground_running;
				if (process.get_optional_value ("foregroundRunning", out foreground_running))
					info.foreground_running = foreground_running.boolean;

				NSDate? start_date;
				if (process.get_optional_value ("startDate", out start_date))
					info.start_date = start_date.to_date_time ();

				result.add (info);
			}

			return result;
		}

		public async CsSignature query_symbolicator_signature (uint pid, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var args = new DTXArgumentListBuilder ()
				.append_object (new NSNumber.from_integer (pid))
				.append_object (new NSString (""));
			var response = yield channel.invoke ("symbolicatorSignatureForPid:trackingSelector:", args, cancellable);

			NSData? data = response as NSData;
			if (data == null)
				throw new Efni.Error.PROTOCOL ("Malformed response");

			var parser = new CsSignatureParser (data.bytes);
			return parser.parse ();
		}

		private static string resolve_real_app_name (string name) {
			if (name.has_prefix ("/var/"))
				return "/private" + name;
			return name;
		}

		public sealed class ProcessInfo : Object {
			public uint pid {
				get;
				set;
			}

			public string name {
				get;
				set;
			}

			public string real_app_name {
				get;
				set;
			}

			public bool is_application {
				get;
				set;
			}

			public bool foreground_running {
				get;
				set;
			}

			public DateTime? start_date {
				get;
				set;
			}
		}
	}
}
