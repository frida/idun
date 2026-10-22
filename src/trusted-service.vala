using Efni;

namespace Idun {
	public abstract class TrustedService : Object, AsyncInitable {
		public IOStream stream {
			get;
			construct;
		}

		private XpcConnection connection;

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Efni.Error, IOError {
			connection = new XpcConnection (stream);
			connection.activate ();

			return true;
		}

		public void close () {
			connection.cancel ();
		}

		protected async VariantReader invoke (string feature_identifier, Bytes? input = null, Cancellable? cancellable)
				throws Efni.Error, IOError {
			var request = new XpcBodyBuilder ()
				.begin_dictionary ()
					.set_member_name ("CoreDevice.featureIdentifier")
					.add_string_value (feature_identifier)
					.set_member_name ("CoreDevice.action")
					.begin_dictionary ()
					.end_dictionary ()
					.set_member_name ("CoreDevice.input");

			if (input != null)
				request.add_raw_value (input);
			else
				request.add_null_value ();

			add_standard_request_values (request);
			request.end_dictionary ();

			XpcMessage raw_response = yield connection.request (request.build (), cancellable);

			var response = new VariantReader (raw_response.body);
			if (!response.has_member ("CoreDevice.output"))
				throw new Efni.Error.NOT_SUPPORTED ("%s", describe_invocation_error (response));
			response.read_member ("CoreDevice.output");
			return response;
		}

		private static string describe_invocation_error (VariantReader response) throws Efni.Error {
			response.read_member ("CoreDevice.error");

			string domain = response.read_member ("domain").get_string_value ();
			response.end_member ();
			int64 code = response.read_member ("code").get_int64_value ();
			response.end_member ();

			response.read_member ("userInfo");
			foreach (unowned string key in new string[] { "NSLocalizedDescription", "NSDebugDescription" }) {
				if (response.has_member (key))
					return response.read_member (key).get_string_value ();
			}

			return ("%s error %" + int64.FORMAT_MODIFIER + "d").printf (domain, code);
		}

		public static void add_standard_request_values (ObjectBuilder builder) {
			builder
				.set_member_name ("CoreDevice.invocationIdentifier")
				.add_string_value (Uuid.string_random ().up ())
				.set_member_name ("CoreDevice.CoreDeviceDDIProtocolVersion")
				.add_int64_value (0)
				.set_member_name ("CoreDevice.coreDeviceVersion")
				.begin_dictionary ()
					.set_member_name ("originalComponentsCount")
					.add_int64_value (2)
					.set_member_name ("components")
					.begin_array ()
						.add_uint64_value (348)
						.add_uint64_value (1)
						.add_uint64_value (0)
						.add_uint64_value (0)
						.add_uint64_value (0)
					.end_array ()
					.set_member_name ("stringValue")
					.add_string_value ("348.1")
				.end_dictionary ()
				.set_member_name ("CoreDevice.deviceIdentifier")
				.add_string_value (make_host_identifier ());
		}
	}
}
