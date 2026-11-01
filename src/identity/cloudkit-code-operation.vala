using Efni;

namespace Idun {
	/**
	 * A CloudKit code-function invocation: the request Idun sends through the CloudKit
	 * code router to call one of Cuttlefish's server functions. The function name selects
	 * the Cuttlefish operation (for example fetchViableBottles), the service name routes
	 * it, and the serialized parameters carry the Cuttlefish request protobuf itself. This
	 * is the inner request that a CloudKit request operation wraps around the account's
	 * Octagon trust calls.
	 */
	public sealed class CloudKitCodeFunctionInvokeRequest : Object {
		public string function_name {
			get;
			construct;
		}

		public string service_name {
			get;
			construct;
		}

		public Bytes serialized_parameters {
			get;
			construct;
		}

		public CloudKitCodeFunctionInvokeRequest (string function_name, string service_name,
				Bytes serialized_parameters) {
			Object (function_name: function_name, service_name: service_name,
				serialized_parameters: serialized_parameters);
		}

		public int trusted_target_scheme {
			get;
			set;
			default = -1;
		}

		public uint8[] serialize () {
			var writer = new ProtobufWriter ()
				.append_bytes (1, service_name.data)
				.append_bytes (2, function_name.data)
				.append_bytes (3, serialized_parameters.get_data ());
			if (trusted_target_scheme >= 0) {
				uint8[] metadata = new ProtobufWriter ()
					.append_varint (4, trusted_target_scheme)
					.data;
				writer.append_bytes (6, metadata);
			}
			return writer.data;
		}

		public static CloudKitCodeFunctionInvokeRequest parse (uint8[] data) throws Efni.Error {
			string function_name = "";
			string service_name = "";
			Bytes serialized_parameters = new Bytes ({});

			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						service_name = reader.read_string ();
						break;
					case 2:
						function_name = reader.read_string ();
						break;
					case 3:
						serialized_parameters = new Bytes (reader.read_bytes ());
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}

			return new CloudKitCodeFunctionInvokeRequest (function_name, service_name,
				serialized_parameters);
		}
	}

	/**
	 * A CloudKit request operation: the top-level message the CloudKit code router expects.
	 * It pairs the per-request header with the operation itself; for Cuttlefish calls the
	 * operation is a code-function invocation, which the router dispatches to the Cuttlefish
	 * server function named inside it.
	 */
	public sealed class CloudKitRequestOperation : Object {
		private const int HEADER_FIELD = 1;
		private const int REQUEST_FIELD = 2;

		public const int FUNCTION_INVOKE_FIELD = 1101;
		public const int USER_RETRIEVE_FIELD = 400;
		public const int TOKEN_REGISTRATION_FIELD = 800;
		public const int RECORD_RETRIEVE_CHANGES_FIELD = 213;

		/**
		 * Extract one operation's response bytes from a length-delimited response operation: the
		 * leading varint frames the message, and the operation rides the field whose number names
		 * it (for example {@link RECORD_RETRIEVE_CHANGES_FIELD}).
		 */
		public static uint8[] parse_operation_field (uint8[] body, int field) throws Efni.Error {
			var reader = new ProtobufReader (body);
			reader.read_varint ();
			while (reader.has_more) {
				uint8 wire_type;
				if (reader.read_field (out wire_type) == field && wire_type == 2)
					return reader.read_bytes ();
				reader.skip (wire_type);
			}
			throw new Efni.Error.PROTOCOL ("CloudKit response has no operation field %d", field);
		}

		/**
		 * Wrap one CloudKit operation in a request operation. The operation message rides the
		 * field whose number names the operation, and the request echoes that number as its
		 * operation type, which is how the router dispatches the operation.
		 */
		public static uint8[] serialize (uint8[] header, string operation_uuid, int operation_field,
				uint8[] operation) {
			uint8[] request = new ProtobufWriter ()
				.append_bytes (1, operation_uuid.data)
				.append_varint (2, operation_field)
				.append_varint (4, 1)
				.data;
			return new ProtobufWriter ()
				.append_bytes (HEADER_FIELD, header)
				.append_bytes (REQUEST_FIELD, request)
				.append_bytes (operation_field, operation)
				.data;
		}

		/**
		 * Unwrap a code-router response to the bytes the Cuttlefish function returned. The HTTP
		 * body is a length-delimited {@link CloudKitRequestOperation} response whose
		 * {@link FUNCTION_INVOKE_FIELD} holds the function-invoke response, and that response's
		 * field 1 is the serialized function result.
		 */
		public static uint8[] parse_function_result (uint8[] body) throws Efni.Error {
			var outer = new ProtobufReader (body);
			outer.read_varint ();

			uint8[]? invoke_response = null;
			while (outer.has_more) {
				uint8 wire_type;
				if (outer.read_field (out wire_type) == FUNCTION_INVOKE_FIELD && wire_type == 2)
					invoke_response = outer.read_bytes ();
				else
					outer.skip (wire_type);
			}
			if (invoke_response == null)
				throw new Efni.Error.PROTOCOL ("CloudKit response carried no function-invoke operation");

			uint8[]? result = null;
			var reader = new ProtobufReader (invoke_response);
			while (reader.has_more) {
				uint8 wire_type;
				if (reader.read_field (out wire_type) == 1 && wire_type == 2)
					result = reader.read_bytes ();
				else
					reader.skip (wire_type);
			}
			if (result == null)
				throw new Efni.Error.PROTOCOL ("CloudKit function-invoke response carried no result");
			return result;
		}

		/**
		 * The device-token registration a device sends to the device service to bind its push
		 * token to the container and activate its CloudKit session.
		 */
		public static uint8[] token_registration (Bytes push_token, string bundle_identifier,
				int apns_environment) {
			uint8[] body = new ProtobufWriter ()
				.append_bytes (1, push_token.get_data ())
				.append_bytes (2, bundle_identifier.data)
				.append_varint (3, apns_environment)
				.data;
			return new ProtobufWriter ().append_bytes (1, body).data;
		}

		/**
		 * The user-retrieve request a device sends to resolve its server-assigned user record,
		 * whose name scopes every later request to the account. It carries no parameters.
		 */
		public static uint8[] user_retrieve () {
			return new uint8[0];
		}
	}

	/**
	 * The CloudKit request header: the device and application context every CloudKit request
	 * carries. Idun fills the fields that identify its application container and device so the
	 * code router accepts the request and routes it to Cuttlefish.
	 */
	public sealed class CloudKitRequestHeader : Object {
		public string application_container {
			get;
			set;
			default = "";
		}

		public string application_bundle {
			get;
			set;
			default = "";
		}

		public string device_identifier {
			get;
			set;
			default = "";
		}

		public string device_name {
			get;
			set;
			default = "";
		}

		public string device_hardware_version {
			get;
			set;
			default = "";
		}

		public string device_software_version {
			get;
			set;
			default = "";
		}

		public string device_serial_number {
			get;
			set;
			default = "";
		}

		public string stable_identifier {
			get;
			set;
			default = "";
		}

		public string client_info {
			get;
			set;
			default = "";
		}

		private const string LIBRARY_NAME = "com.apple.cloudkit.CloudKitDaemon";
		private const string LIBRARY_VERSION = "2710.120";
		private const string PROTOCOL_VERSION = "5.0";

		public uint8[] serialize () {
			return new ProtobufWriter ()
				.append_bytes (2, application_container.data)
				.append_bytes (3, application_bundle.data)
				.append_bytes (7, identifier (device_identifier))
				.append_bytes (8, device_software_version.data)
				.append_bytes (9, device_hardware_version.data)
				.append_bytes (10, LIBRARY_NAME.data)
				.append_bytes (11, LIBRARY_VERSION.data)
				.append_bytes (18, PROTOCOL_VERSION.data)
				.append_varint (19, 1)
				.append_bytes (21, device_name.data)
				.append_bytes (22, device_identifier.data)
				.append_varint (23, 1)
				.append_varint (25, 1)
				.append_varint (29, 0)
				.append_bytes (30, client_info_dict ())
				.append_bytes (32, stable_identifier.data)
				.append_bytes (33, device_serial_number.data)
				.append_varint (34, 0)
				.append_varint (35, 5)
				.data;
		}

		private uint8[] client_info_dict () {
			return new ProtobufWriter ()
				.append_bytes (1, pair ("x-mme-client-info", client_info))
				.append_varint (2, 0)
				.data;
		}

		private static uint8[] pair (string key, string value) {
			return new ProtobufWriter ()
				.append_bytes (1, key.data)
				.append_bytes (2, value.data)
				.data;
		}

		private static uint8[] identifier (string name) {
			return new ProtobufWriter ()
				.append_bytes (1, name.data)
				.append_varint (2, 2)
				.data;
		}
	}
}
