using Efni;

namespace Idun {
	/**
	 * A minimal CloudKit client for the code router: it invokes Cuttlefish's server
	 * functions, which hold the account's Octagon trust state. Idun authenticates with the
	 * CloudKit token from its mobileme delegate, wraps a Cuttlefish request in a CloudKit
	 * request operation, and posts it gzip-compressed to the code router, returning the raw
	 * response operation for the caller to decode.
	 */
	public sealed class CloudKitClient : Object {
		public CloudKitCredentials credentials {
			get;
			construct;
		}

		public string device_identifier {
			get;
			set;
			default = "";
		}

		public string stable_identifier {
			get;
			set;
			default = "";
		}

		public DeviceIdentity? device_info {
			get;
			set;
			default = null;
		}

		public int trusted_target_scheme {
			get;
			set;
			default = -1;
		}

		public int operation_type {
			get;
			set;
			default = 1101;
		}

		public bool omit_user_id {
			get;
			set;
			default = false;
		}

		public Gee.Map<string, string>? extra_headers {
			get;
			set;
			default = null;
		}

		public string auth_token_override {
			get;
			set;
			default = "";
		}

		private Soup.Session session = new Soup.Session ();

		private const string CONTAINER_ID = "com.apple.security.keychain";
		private const string BUNDLE_ID = "com.apple.security.cuttlefish";
		private const string ENVIRONMENT = "Production";
		private const string DATABASE_SCOPE = "Private";
		private const string SERVICE_NAME = "Cuttlefish";
		private const int APNS_PRODUCTION = 1;
		private const string CK_APP_INIT_URL = "https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit";
		private const string CK_DATABASE_SYNC_URL = "https://gateway.icloud.com/ckdatabase/api/client/record/sync";
		private const string SECURITYD_BUNDLE = "com.apple.securityd";
		private const string USER_AGENT = "CloudKit/2710.120 (26A428)";
		private const string MME_CLIENT_INFO =
			"<Mac17,2> <macOS;27.0;26A428> <com.apple.cloudkit.CloudKitDaemon/2710.120 (com.apple.cloudd/2710.120)>";
		private const string CONTENT_TYPE =
			"application/x-protobuf; desc=\"https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc\"; messageType=RequestOperation; delimited=true";

		public CloudKitClient (CloudKitCredentials credentials) {
			Object (credentials: credentials);
		}

		public string scoped_user_id {
			get;
			set;
			default = "";
		}

		/**
		 * Resolve the CloudKit user id that scopes every later request to this account. The id is
		 * the per-container {@link scoped_user_id} the ckAppInit handshake returns — not the
		 * directory id's digest, which CloudKit rejects — so this must run before any code-router
		 * call. The push token is unused but kept for callers that expect a bootstrap step.
		 */
		public async string bootstrap (Bytes push_token, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			return yield app_init (cancellable);
		}

		/**
		 * The ckAppInit handshake: authenticates with the mobileme Basic credential and the
		 * account's anisette, and returns the container-scoped CloudKit user id. CloudKit keys its
		 * code-router auth on this id paired with the CloudKit token, so {@link scoped_user_id} is
		 * set from it here.
		 */
		public async string app_init (Cancellable? cancellable = null) throws Efni.Error, IOError {
			var message = new Soup.Message ("POST",
				CK_APP_INIT_URL + "?container=" + CONTAINER_ID);
			var headers = message.request_headers;
			headers.replace ("Authorization", "Basic " + Base64.encode (
				"%s:%s".printf (credentials.dsid, credentials.mme_auth_token).data));
			headers.replace ("X-CloudKit-ContainerId", CONTAINER_ID);
			headers.replace ("X-CloudKit-BundleId", BUNDLE_ID);
			headers.replace ("X-CloudKit-Environment", ENVIRONMENT);
			headers.replace ("X-CloudKit-DatabaseScope", DATABASE_SCOPE);
			headers.replace ("X-CloudKit-DuetPreClearedMode", "None");
			headers.replace ("X-MMe-Client-Info", MME_CLIENT_INFO);
			headers.replace ("Accept", "application/json");
			headers.replace ("Cache-Control", "no-transform");
			headers.replace ("User-Agent", USER_AGENT);
			if (extra_headers != null) {
				foreach (var entry in extra_headers.entries)
					headers.replace (entry.key, entry.value);
			}
			message.set_request_body_from_bytes (null, new Bytes ({}));

			Bytes response;
			try {
				response = yield session.send_and_read_async (message, Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to reach ckAppInit: %s", e.message);
			}
			if (message.status_code != 200) {
				throw new Efni.Error.PROTOCOL ("ckAppInit returned HTTP %u: %s", message.status_code,
					(string) response.get_data ());
			}

			var parser = new Json.Parser ();
			try {
				parser.load_from_data ((string) response.get_data (), (ssize_t) response.length);
			} catch (GLib.Error e) {
				throw new Efni.Error.PROTOCOL ("Malformed ckAppInit response: %s", e.message);
			}
			var root = parser.get_root ();
			if (root == null || root.get_node_type () != Json.NodeType.OBJECT)
				throw new Efni.Error.PROTOCOL ("ckAppInit response is not a JSON object");
			var obj = root.get_object ();
			if (!obj.has_member ("cloudKitUserId"))
				throw new Efni.Error.PROTOCOL ("ckAppInit response has no cloudKitUserId");
			scoped_user_id = obj.get_string_member ("cloudKitUserId");
			return scoped_user_id;
		}

		public async Bytes invoke (string function_name, Bytes parameters, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			var function_invoke = new CloudKitCodeFunctionInvokeRequest (function_name, SERVICE_NAME,
				parameters);
			function_invoke.trusted_target_scheme = trusted_target_scheme;
			Bytes response = yield send_operation (credentials.ck_code_gateway_url + "/api/client/code/invoke",
				CloudKitRequestOperation.FUNCTION_INVOKE_FIELD, function_invoke.serialize (),
				SERVICE_NAME + "/" + function_name, scoped_user_id != "", cancellable);
			return new Bytes (CloudKitRequestOperation.parse_function_result (response.get_data ()));
		}

		/**
		 * Fetch one page of record changes from a CKKS zone. CKKS stores the account's keychain in
		 * CloudKit record zones (Manatee, Passwords, …) under the securityd bundle, reached through
		 * the record-sync operation rather than a Cuttlefish code function. Returns the raw
		 * retrieve-changes response for {@link CkksZone.parse_page} to decode.
		 */
		public async Bytes fetch_zone_records (uint8[] zone_request, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			Bytes response = yield send_operation (CK_DATABASE_SYNC_URL,
				CloudKitRequestOperation.RECORD_RETRIEVE_CHANGES_FIELD, zone_request, null,
				scoped_user_id != "", cancellable, SECURITYD_BUNDLE);
			return new Bytes (CloudKitRequestOperation.parse_operation_field (response.get_data (),
				CloudKitRequestOperation.RECORD_RETRIEVE_CHANGES_FIELD));
		}

		private async Bytes send_operation (string url, int operation_field, uint8[] operation,
				string? routing_hint, bool include_user_id, Cancellable? cancellable,
				string bundle = BUNDLE_ID)
				throws Efni.Error, IOError {
			uint8[] envelope = CloudKitRequestOperation.serialize (build_header (bundle).serialize (),
				Uuid.string_random ().up (), operation_field, operation);
			Bytes body = gzip (new Bytes (delimit (envelope)));

			var message = new Soup.Message ("POST", url);
			apply_headers (message, routing_hint, include_user_id, bundle);
			message.set_request_body_from_bytes ("application/x-protobuf", body);

			try {
				Bytes response = yield session.send_and_read_async (message, Priority.DEFAULT, cancellable);
				if (Environment.get_variable ("IDUN_CK_DEBUG") != null) {
					print ("HTTP %u %s\n", message.status_code, url);
					message.response_headers.foreach ((name, val) => {
						print ("  %s: %s\n", name, val);
					});
					var hex = new StringBuilder ();
					foreach (uint8 b in response.get_data ())
						hex.append_printf ("%02x", b);
					print ("  body[%u]: %s\n", response.length, hex.str);
				}
				if (message.status_code != 200)
					throw new Efni.Error.PROTOCOL ("CloudKit returned HTTP %u", message.status_code);
				return response;
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to reach CloudKit: %s", e.message);
			}
		}

		private CloudKitRequestHeader build_header (string bundle = BUNDLE_ID) {
			var header = new CloudKitRequestHeader ();
			header.application_container = CONTAINER_ID;
			header.application_bundle = bundle;
			header.device_identifier = device_identifier;
			header.stable_identifier = stable_identifier;
			header.device_name = "idun";
			if (device_info != null) {
				header.device_hardware_version = device_info.hardware_version;
				header.device_software_version = device_info.software_version;
				header.device_serial_number = device_info.serial_number;
				header.client_info = "<%s> <macOS;%s;%s> <com.apple.icloud.content/unknown (com.apple.CloudKit/(null))>".printf (
					device_info.hardware_version, device_info.software_version, device_info.software_build_id);
			}
			return header;
		}

		private void apply_headers (Soup.Message message, string? routing_hint, bool include_user_id,
				string bundle = BUNDLE_ID) {
			var headers = message.request_headers;
			headers.replace ("X-CloudKit-AuthToken",
				(auth_token_override != "") ? auth_token_override : credentials.cloud_kit_token);
			headers.replace ("X-CloudKit-ContainerId", CONTAINER_ID);
			headers.replace ("X-CloudKit-BundleId", bundle);
			headers.replace ("X-CloudKit-Environment", ENVIRONMENT);
			headers.replace ("X-CloudKit-DatabaseScope", DATABASE_SCOPE);
			if (include_user_id)
				headers.replace ("X-CloudKit-UserId", user_id ());
			if (routing_hint != null)
				headers.replace ("X-CloudKit-FunctionRoutingHint", routing_hint);
			headers.replace ("X-CloudKit-DuetPreClearedMode", "None");
			headers.replace ("X-CloudKit-Network-Service-Type", "6");
			headers.replace ("X-MMe-Client-Info", MME_CLIENT_INFO);
			headers.replace ("X-Apple-Request-UUID", Uuid.string_random ().up ());
			headers.replace ("X-Apple-Operation-ID", random_operation_id ());
			headers.replace ("Content-Type", CONTENT_TYPE);
			headers.replace ("Content-Encoding", "gzip");
			headers.replace ("Accept", "application/x-protobuf");
			headers.replace ("Accept-Encoding", "gzip");
			headers.replace ("Cache-Control", "no-transform");
			headers.replace ("User-Agent", USER_AGENT);

			if (extra_headers != null) {
				foreach (var entry in extra_headers.entries)
					headers.replace (entry.key, entry.value);
			}
		}

		/**
		 * The CloudKit user id that scopes the request to the account: the server-assigned
		 * record name once the device bootstrap has resolved it, falling back to the directory
		 * id's digest before then.
		 */
		public string user_id () {
			if (scoped_user_id != "")
				return scoped_user_id;
			return "_" + Checksum.compute_for_string (ChecksumType.MD5, credentials.dsid);
		}

		/**
		 * Recover the server-assigned user record name from a user-retrieve response: it is the
		 * underscore-prefixed identifier the response carries for this device's account.
		 */
		private static string find_scoped_user_id (Bytes response) throws Efni.Error {
			uint8[] body = response.get_data ();
			if (body.length >= 2 && body[0] == 0x1f && body[1] == 0x8b)
				body = gunzip (response);
			string text = (string) body;
			for (int i = 0; i < text.length; i++) {
				if (text[i] != '_')
					continue;
				int j = i + 1;
				while (j < text.length && text[j].isxdigit ())
					j++;
				if (j - i == 33)
					return text[i : j];
			}
			return "";
		}

		/**
		 * Prepend the message length as a varint, the length-delimited framing the code router
		 * expects for a single request operation.
		 */
		private static string random_operation_id () {
			var id = new uint8[8];
			OpenSSL.Rng.generate (id);
			var sb = new StringBuilder ();
			foreach (uint8 b in id)
				sb.append_printf ("%02X", b);
			return sb.str;
		}

		private static uint8[] delimit (uint8[] message) {
			var framed = new ByteArray ();
			uint64 length = message.length;
			do {
				uint8 piece = (uint8) (length & 0x7f);
				length >>= 7;
				if (length != 0)
					piece |= 0x80;
				framed.append ({ piece });
			} while (length != 0);
			framed.append (message);
			return framed.data;
		}

		private static Bytes gzip (Bytes data) throws Efni.Error {
			try {
				var source = new ConverterInputStream (new MemoryInputStream.from_bytes (data),
					new ZlibCompressor (ZlibCompressorFormat.GZIP));
				var sink = new MemoryOutputStream.resizable ();
				sink.splice (source, OutputStreamSpliceFlags.CLOSE_SOURCE | OutputStreamSpliceFlags.CLOSE_TARGET);
				return sink.steal_as_bytes ();
			} catch (GLib.Error e) {
				throw new Efni.Error.PROTOCOL ("Unable to compress CloudKit request: %s", e.message);
			}
		}

		private static uint8[] gunzip (Bytes data) throws Efni.Error {
			try {
				var source = new ConverterInputStream (new MemoryInputStream.from_bytes (data),
					new ZlibDecompressor (ZlibCompressorFormat.GZIP));
				var sink = new MemoryOutputStream.resizable ();
				sink.splice (source, OutputStreamSpliceFlags.CLOSE_SOURCE | OutputStreamSpliceFlags.CLOSE_TARGET);
				return sink.steal_as_bytes ().get_data ();
			} catch (GLib.Error e) {
				throw new Efni.Error.PROTOCOL ("Unable to decompress CloudKit response: %s", e.message);
			}
		}
	}
}
