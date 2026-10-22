using Efni;

namespace Idun {
	public sealed class AppService : TrustedService {
		public static async AppService open (IOStream stream, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var service = new AppService (stream);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private AppService (IOStream stream) {
			Object (stream: stream);
		}

		public async Gee.List<ApplicationInfo> enumerate_applications (Cancellable? cancellable = null) throws Efni.Error, IOError {
			Bytes input = new XpcObjectBuilder ()
				.begin_dictionary ()
					.set_member_name ("includeDefaultApps")
					.add_bool_value (true)
					.set_member_name ("includeRemovableApps")
					.add_bool_value (true)
					.set_member_name ("includeInternalApps")
					.add_bool_value (true)
					.set_member_name ("includeHiddenApps")
					.add_bool_value (true)
					.set_member_name ("includeAppClips")
					.add_bool_value (true)
				.end_dictionary ()
				.build ();
			var response = yield invoke ("com.apple.coredevice.feature.listapps", input, cancellable);

			var applications = new Gee.ArrayList<ApplicationInfo> ();
			uint n = response.count_elements ();
			for (uint i = 0; i != n; i++) {
				response.read_element (i);

				string bundle_identifier = response
					.read_member ("bundleIdentifier")
					.get_string_value ();
				response.end_member ();

				string? bundle_version = null;
				if (response.has_member ("bundleVersion")) {
					bundle_version = response
						.read_member ("bundleVersion")
						.get_string_value ();
					response.end_member ();
				}

				string name = response
					.read_member ("name")
					.get_string_value ();
				response.end_member ();

				string? version = null;
				if (response.has_member ("version")) {
					version = response
						.read_member ("version")
						.get_string_value ();
					response.end_member ();
				}

				string path = response
					.read_member ("path")
					.get_string_value ();
				response.end_member ();

				bool is_first_party = response
					.read_member ("isFirstParty")
					.get_bool_value ();
				response.end_member ();

				bool is_developer_app = response
					.read_member ("isDeveloperApp")
					.get_bool_value ();
				response.end_member ();

				bool is_removable = response
					.read_member ("isRemovable")
					.get_bool_value ();
				response.end_member ();

				bool is_internal = response
					.read_member ("isInternal")
					.get_bool_value ();
				response.end_member ();

				bool is_hidden = response
					.read_member ("isHidden")
					.get_bool_value ();
				response.end_member ();

				bool is_app_clip = response
					.read_member ("isAppClip")
					.get_bool_value ();
				response.end_member ();

				applications.add (new ApplicationInfo () {
					bundle_identifier = bundle_identifier,
					bundle_version = bundle_version,
					name = name,
					version = version,
					path = path,
					is_first_party = is_first_party,
					is_developer_app = is_developer_app,
					is_removable = is_removable,
					is_internal = is_internal,
					is_hidden = is_hidden,
					is_app_clip = is_app_clip,
				});

				response.end_element ();
			}

			return applications;
		}

		public async Gee.List<ProcessInfo> enumerate_processes (Cancellable? cancellable = null) throws Efni.Error, IOError {
			var response = yield invoke ("com.apple.coredevice.feature.listprocesses", null, cancellable);

			var processes = new Gee.ArrayList<ProcessInfo> ();
			uint n = response
				.read_member ("processTokens")
				.count_elements ();
			for (uint i = 0; i != n; i++) {
				response.read_element (i);
				processes.add (parse_process_token (response));
				response.end_element ();
			}

			return processes;
		}

		/**
		 * Launches an application, optionally handing it a URL to open.
		 *
		 * The URL is delivered through the launch payload, so it reaches the app the same way a
		 * tapped link would, which makes it possible to drive URL schemes such as facetime:// or
		 * facetime-audio:// from the host.
		 */
		public async ProcessInfo launch_application (string bundle_identifier, LaunchOptions? options = null,
				Cancellable? cancellable = null) throws Efni.Error, IOError {
			LaunchOptions opts = (options != null) ? options : new LaunchOptions ();

			var builder = new XpcObjectBuilder ();
			builder
				.begin_dictionary ()
					.set_member_name ("applicationSpecifier")
					.begin_dictionary ()
						.set_member_name ("bundleIdentifier")
						.begin_dictionary ()
							.set_member_name ("_0")
							.add_string_value (bundle_identifier)
						.end_dictionary ()
					.end_dictionary ()
					.set_member_name ("options")
					.begin_dictionary ()
						.set_member_name ("arguments")
						.begin_array ();
			foreach (unowned string arg in opts.arguments)
				builder.add_string_value (arg);
			builder
						.end_array ()
						.set_member_name ("environmentVariables")
						.begin_dictionary ();
			foreach (var e in opts.environment.entries) {
				builder
							.set_member_name (e.key)
							.add_string_value (e.value);
			}
			builder
						.end_dictionary ()
						.set_member_name ("standardIOUsesPseudoterminals")
						.add_bool_value (false)
						.set_member_name ("startStopped")
						.add_bool_value (opts.start_stopped)
						.set_member_name ("terminateExisting")
						.add_bool_value (opts.terminate_existing)
						.set_member_name ("user")
						.begin_dictionary ()
							.set_member_name ("active")
							.add_bool_value (true)
						.end_dictionary ()
						.set_member_name ("platformSpecificOptions")
						.add_data_value (new Bytes (new Plist ().to_xml ().data));
			if (opts.payload_url != null) {
				builder
						.set_member_name ("payloadURL")
						.begin_dictionary ()
							.set_member_name ("relative")
							.add_string_value (opts.payload_url)
						.end_dictionary ();
			}
			builder
					.end_dictionary ()
					.set_member_name ("standardIOIdentifiers")
					.begin_dictionary ()
					.end_dictionary ()
				.end_dictionary ();

			var response = yield invoke ("com.apple.coredevice.feature.launchapplication", builder.build (), cancellable);

			response.read_member ("processToken");
			return parse_process_token (response);
		}

		private static ProcessInfo parse_process_token (VariantReader response) throws Efni.Error {
			int64 pid = response
				.read_member ("processIdentifier")
				.get_int64_value ();
			response.end_member ();

			string url = response
				.read_member ("executableURL")
				.read_member ("relative")
				.get_string_value ();
			response
				.end_member ()
				.end_member ();

			if (!url.has_prefix ("file://"))
				throw new Efni.Error.PROTOCOL ("Unsupported URL: %s", url);

			return new ProcessInfo () {
				pid = (uint) pid,
				path = url[7:],
			};
		}

		public sealed class ApplicationInfo {
			public string bundle_identifier;
			public string? bundle_version;
			public string name;
			public string? version;
			public string path;
			public bool is_first_party;
			public bool is_developer_app;
			public bool is_removable;
			public bool is_internal;
			public bool is_hidden;
			public bool is_app_clip;
		}

		public sealed class ProcessInfo : Object {
			public uint pid {
				get;
				set;
			}

			public string path {
				get;
				set;
			}
		}

		public sealed class LaunchOptions : Object {
			public string[] arguments {
				get;
				set;
				default = {};
			}

			public Gee.Map<string, string> environment {
				get;
				set;
				default = new Gee.HashMap<string, string> ();
			}

			public bool terminate_existing {
				get;
				set;
				default = false;
			}

			public bool start_stopped {
				get;
				set;
				default = false;
			}

			/**
			 * URL handed to the application at launch, as if the user had opened it.
			 */
			public string? payload_url {
				get;
				set;
			}
		}
	}
}
