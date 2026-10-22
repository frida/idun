using Efni;

namespace Idun {
	public sealed class ApplicationListingService : Object, AsyncInitable {
		public ChannelProvider channel_provider {
			get;
			construct;
		}

		private DTXChannel channel;

		private ApplicationListingService (ChannelProvider channel_provider) {
			Object (channel_provider: channel_provider);
		}

		public static async ApplicationListingService open (ChannelProvider channel_provider, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			var service = new ApplicationListingService (channel_provider);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Efni.Error, IOError {
			var connection = yield DTXConnection.obtain (channel_provider, cancellable);

			channel = connection.make_channel ("com.apple.instruments.server.services.device.applictionListing");

			return true;
		}

		public async Gee.List<ApplicationInfo> enumerate_applications (NSDictionary? query = null,
				Cancellable? cancellable = null) throws Efni.Error, IOError {
			var result = new Gee.ArrayList<ApplicationInfo> ();

			var args = new DTXArgumentListBuilder ()
				.append_object ((query != null) ? query : new NSDictionary ())
				.append_object (new NSString (""));
			var response = yield channel.invoke ("installedApplicationsMatching:registerUpdateToken:", args, cancellable);

			NSArray? apps = response as NSArray;
			if (apps == null)
				throw new Efni.Error.PROTOCOL ("Malformed response");

			foreach (var element in apps.elements) {
				NSDictionary? app = element as NSDictionary;
				if (app == null)
					throw new Efni.Error.PROTOCOL ("Malformed response");

				var info = new ApplicationInfo ();

				info.app_type = ApplicationType.from_dtx (app.get_value<NSString> ("Type").str);
				info.display_name = app.get_value<NSString> ("DisplayName").str;
				info.bundle_identifier = app.get_value<NSString> ("CFBundleIdentifier").str;
				info.bundle_path = app.get_value<NSString> ("BundlePath").str;
				info.restricted = app.get_value<NSNumber> ("Restricted").boolean;

				NSNumber num_val;
				NSString? str_val;
				NSArray arr_val;

				if (app.get_optional_value<NSString> ("Version", out str_val))
					info.version = str_val.str;

				if (app.get_optional_value<NSNumber> ("Placeholder", out num_val))
					info.placeholder = num_val.boolean;

				if (app.get_optional_value<NSString> ("ExecutableName", out str_val))
					info.executable_name = str_val.str;

				if (app.get_optional_value<NSArray> ("AppExtensionUUIDs", out arr_val)) {
					var uuids = new string[arr_val.length];
					uint i = 0;
					foreach (var uuid in arr_val.elements) {
						str_val = uuid as NSString;
						if (str_val == null)
							throw new Efni.Error.PROTOCOL ("Malformed response");
						uuids[i] = str_val.str;
						i++;
					}
					info.app_extension_uuids = uuids;
				}

				if (app.get_optional_value<NSString> ("PluginUUID", out str_val))
					info.plugin_uuid = str_val.str;

				if (app.get_optional_value<NSString> ("PluginIdentifier", out str_val))
					info.plugin_identifier = str_val.str;

				if (app.get_optional_value<NSString> ("ContainerBundleIdentifier", out str_val))
					info.container_bundle_identifier = str_val.str;

				if (app.get_optional_value<NSString> ("ContainerBundlePath", out str_val))
					info.container_bundle_path = str_val.str;

				result.add (info);
			}

			return result;
		}

		public sealed class ApplicationInfo : Object {
			public ApplicationType app_type {
				get;
				set;
			}

			public string display_name {
				get;
				set;
			}

			public string bundle_identifier {
				get;
				set;
			}

			public string bundle_path {
				get;
				set;
			}

			public string? version {
				get;
				set;
			}

			public bool placeholder {
				get;
				set;
			}

			public bool restricted {
				get;
				set;
			}

			public string? executable_name {
				get;
				set;
			}

			public string[]? app_extension_uuids {
				get;
				set;
			}

			public string? plugin_uuid {
				get;
				set;
			}

			public string? plugin_identifier {
				get;
				set;
			}

			public string? container_bundle_identifier {
				get;
				set;
			}

			public string? container_bundle_path {
				get;
				set;
			}
		}

		public enum ApplicationType {
			SYSTEM = 1,
			USER,
			PLUGIN_KIT;

			public static ApplicationType from_nick (string nick) throws Efni.Error {
				return Marshal.enum_from_nick<ApplicationType> (nick);
			}

			public string to_nick () {
				return Marshal.enum_to_nick<ApplicationType> (this);
			}

			internal static ApplicationType from_dtx (string type) {
				if (type == "System")
					return SYSTEM;

				if (type == "User")
					return USER;

				if (type == "PluginKit")
					return PLUGIN_KIT;

				assert_not_reached ();
			}
		}
	}
}
