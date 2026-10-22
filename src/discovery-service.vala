using Efni;

namespace Idun {
	public sealed class DiscoveryService : Object, AsyncInitable {
		public IOStream stream {
			get;
			construct;
		}

		private XpcConnection connection;

		private Promise<Variant> handshake_promise = new Promise<Variant> ();
		private Variant handshake_body;

		private Cancellable io_cancellable = new Cancellable ();

		public static async DiscoveryService open (IOStream stream, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var service = new DiscoveryService (stream);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private DiscoveryService (IOStream stream) {
			Object (stream: stream);
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Efni.Error, IOError {
			connection = new XpcConnection (stream);
			connection.close.connect (on_close);
			connection.message.connect (on_message);
			connection.activate ();

			handshake_body = yield handshake_promise.future.wait_async (cancellable);

			return true;
		}

		public void close () {
			io_cancellable.cancel ();
			connection.cancel ();
		}

		public string query_udid () throws Efni.Error {
			var reader = new VariantReader (handshake_body);
			reader
				.read_member ("Properties")
				.read_member ("UniqueDeviceID");
			return reader.get_string_value ();
		}

		public ServiceInfo get_service (string identifier) throws Efni.Error {
			ServiceInfo? service = find_service (identifier);
			if (service == null)
				throw new Efni.Error.NOT_SUPPORTED ("Service '%s' not found", identifier);
			return service;
		}

		public ServiceInfo? find_first_service (string[] identifiers) throws Efni.Error {
			foreach (unowned string identifier in identifiers) {
				ServiceInfo? service = find_service (identifier);
				if (service != null)
					return service;
			}

			return null;
		}

		public ServiceInfo? find_service (string identifier) throws Efni.Error {
			var reader = new VariantReader (handshake_body);
			reader.read_member ("Services");
			try {
				reader.read_member (identifier);
			} catch (Efni.Error e) {
				return null;
			}

			return parse_service (identifier, reader);
		}

		/**
		 * Lists the services the device advertised in its handshake, each with the features it supports.
		 */
		public Gee.List<ServiceInfo> query_services () throws Efni.Error {
			var services = new Gee.ArrayList<ServiceInfo> ();

			var reader = new VariantReader (handshake_body);
			reader.read_member ("Services");
			foreach (string identifier in reader.list_members ()) {
				reader.read_member (identifier);
				services.add (parse_service (identifier, reader));
				reader.end_member ();
			}

			return services;
		}

		private static ServiceInfo parse_service (string identifier, VariantReader reader) throws Efni.Error {
			var port = (uint16) uint.parse (reader.read_member ("Port").get_string_value ());
			reader.end_member ();

			var features = new Gee.ArrayList<string> ();
			reader.read_member ("Properties");
			if (reader.has_member ("Features")) {
				reader.read_member ("Features");
				uint n = reader.count_elements ();
				for (uint i = 0; i != n; i++) {
					features.add (reader.read_element (i).get_string_value ());
					reader.end_element ();
				}
				reader.end_member ();
			}
			reader.end_member ();

			return new ServiceInfo () {
				name = identifier,
				port = port,
				features = features,
			};
		}

		private void on_close (Efni.Error? error) {
			if (!handshake_promise.future.ready) {
				handshake_promise.reject (
					(error != null)
						? error
						: new Efni.Error.TRANSPORT ("XpcConnection closed while waiting for Handshake message"));
			}
		}

		private void on_message (XpcMessage msg) {
			if (msg.body == null)
				return;

			var reader = new VariantReader (msg.body);
			try {
				reader.read_member ("MessageType");
				unowned string message_type = reader.get_string_value ();

				if (message_type == "Handshake") {
					handshake_promise.resolve (msg.body);

					connection.post.begin (
						new XpcBodyBuilder ()
							.begin_dictionary ()
								.set_member_name ("MessageType")
								.add_string_value ("Handshake")
								.set_member_name ("MessagingProtocolVersion")
								.add_uint64_value (5)
								.set_member_name ("Services")
								.begin_dictionary ()
								.end_dictionary ()
								.set_member_name ("Properties")
								.begin_dictionary ()
									.set_member_name ("RemoteXPCVersionFlags")
									.add_uint64_value (0x100000000000006)
								.end_dictionary ()
								.set_member_name ("UUID")
								.add_uuid_value (make_random_v4_uuid ())
							.end_dictionary ()
							.build (),
						io_cancellable);
				}
			} catch (Efni.Error e) {
			}
		}
	}

	public class ServiceInfo {
		public string name;
		public uint16 port;
		public Gee.List<string> features;
	}
}
