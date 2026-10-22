using Efni;

namespace Idun {
	public sealed class ProcessControlService : Object, AsyncInitable {
		public signal void process_terminated (uint pid, int exit_code, int crashing_signal);

		public ChannelProvider channel_provider {
			get;
			construct;
		}

		private DTXChannel channel;

		private ProcessControlService (ChannelProvider channel_provider) {
			Object (channel_provider: channel_provider);
		}

		public static async ProcessControlService open (ChannelProvider channel_provider, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			var service = new ProcessControlService (channel_provider);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Efni.Error, IOError {
			var connection = yield DTXConnection.obtain (channel_provider, cancellable);

			channel = connection.make_channel ("com.apple.instruments.server.services.processcontrol");
			channel.invocation.connect (on_invocation);

			return true;
		}

		public async uint process_identifier_for_bundle_identifier (string bundle_id, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			var args = new DTXArgumentListBuilder ()
				.append_object (new NSString (bundle_id));
			var response = yield channel.invoke ("processIdentifierForBundleIdentifier:", args, cancellable);

			NSNumber? pid = response as NSNumber;
			if (pid == null)
				throw new Efni.Error.PROTOCOL ("Malformed response");

			return (uint) pid.integer;
		}

		public async bool is_pid_debuggable (uint pid, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var args = new DTXArgumentListBuilder ()
				.append_object (new NSNumber.from_integer (pid));
			var response = yield channel.invoke ("isPidDebuggable:", args, cancellable);

			NSNumber? is_debuggable = response as NSNumber;
			if (is_debuggable == null)
				throw new Efni.Error.PROTOCOL ("Malformed response");

			return is_debuggable.boolean;
		}

		public async void start_observing_pid (uint pid, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var args = new DTXArgumentListBuilder ()
				.append_object (new NSNumber.from_integer (pid));
			yield channel.invoke ("startObservingPid:", args, cancellable);
		}

		public async void stop_observing_pid (uint pid, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var args = new DTXArgumentListBuilder ()
				.append_object (new NSNumber.from_integer (pid));
			yield channel.invoke ("stopObservingPid:", args, cancellable);
		}

		public async uint launch (string bundle_id, LaunchOptions? options = null, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			var opts = options;
			if (opts == null)
				opts = new LaunchOptions ();

			var args_val = new NSArray ();
			foreach (unowned string arg in opts.arguments)
				args_val.add_object (new NSString (arg));

			var env_val = new NSDictionary ();
			foreach (unowned string entry in opts.environment) {
				string[] tokens = entry.split ("=", 2);
				if (tokens.length != 2)
					throw new Efni.Error.INVALID_ARGUMENT ("Invalid environment variable entry: %s", entry);
				env_val.set_value (tokens[0], new NSString (tokens[1]));
			}

			var opts_val = new NSDictionary ();
			opts_val.set_value ("StartSuspendedKey", new NSNumber.from_boolean (opts.launch_mode == SUSPENDED));
			opts_val.set_value ("KillExisting", new NSNumber.from_boolean (opts.existing_instance_policy == KILL));
			// TODO: Support CaptureOutput + iODestinationKey

			var dtx_args = new DTXArgumentListBuilder ()
				.append_object (new NSString (""))
				.append_object (new NSString (bundle_id))
				.append_object (env_val)
				.append_object (args_val)
				.append_object (opts_val);
			var response = yield channel.invoke (
				"launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:options:",
				dtx_args, cancellable);

			NSNumber? pid = response as NSNumber;
			if (pid == null)
				throw new Efni.Error.PROTOCOL ("Malformed response");

			return (uint) pid.integer;
		}

		public async void kill (uint pid, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var args = new DTXArgumentListBuilder ()
				.append_object (new NSNumber.from_integer (pid));
			yield channel.invoke ("killPid:", args, cancellable);
		}

		public async void send_signal (uint pid, uint sig, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var args = new DTXArgumentListBuilder ()
				.append_object (new NSNumber.from_integer (sig))
				.append_object (new NSNumber.from_integer (pid));
			yield channel.invoke ("sendSignal:toPid:", args, cancellable);
		}

		private void on_invocation (string method_name, DTXArgumentList args, DTXMessageTransportFlags transport_flags) {
			if (method_name == "processWithPID:terminatedWithExitCode:orCrashingSignal:") {
				if (args.elements.length != 3)
					return;

				uint pid;
				if (!try_parse_int (args.elements[0], out pid))
					return;

				int exit_code = -1;
				int crashing_signal = -1;
				if (!try_parse_int (args.elements[1], out exit_code)) {
					if (!try_parse_int (args.elements[2], out crashing_signal))
						return;
				}

				process_terminated (pid, exit_code, crashing_signal);
			}
		}

		private bool try_parse_int (Value v, out int i) {
			i = -1;
			if (!v.holds (typeof (NSNumber)))
				return false;
			i = (int) ((NSNumber) v.get_object ()).integer;
			return true;
		}
	}

	public sealed class LaunchOptions : Object {
		public string[] arguments {
			get;
			set;
			default = {};
		}

		public string[] environment {
			get;
			set;
			default = {};
		}

		public LaunchMode launch_mode {
			get;
			set;
			default = LaunchMode.NORMAL;
		}

		public ExistingInstancePolicy existing_instance_policy {
			get;
			set;
			default = ExistingInstancePolicy.KEEP;
		}
	}

	public enum LaunchMode {
		NORMAL,
		SUSPENDED
	}

	public enum ExistingInstancePolicy {
		KEEP,
		KILL
	}
}
