using Efni;

namespace Idun {
	/**
	 * Client for the identity oracle: a trusted helper that computes the Apple
	 * primitives Idun cannot yet produce on its own. The oracle only computes;
	 * Idun makes every request to Apple's servers itself.
	 */
	public sealed class IdentityOracle : Object {
		public string base_url {
			get;
			construct;
		}

		private Soup.Session session = new Soup.Session ();
		private AppleTrust trust = new AppleTrust ();

		public IdentityOracle (string base_url) {
			Object (base_url: base_url);
		}

		construct {
			trust.guard (session);
		}

		public async DeviceIdentity fetch_device_info (Cancellable? cancellable = null) throws Efni.Error, IOError {
			var message = new Soup.Message ("GET", @"$base_url/device-info");
			return new DeviceIdentity (yield send (message, cancellable));
		}

		public async FairPlaySignature sign_activation (Bytes activation_info, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			var message = new Soup.Message ("POST", @"$base_url/fairplay-sign");
			message.set_request_body_from_bytes ("application/octet-stream", activation_info);
			Json.Object result = yield send (message, cancellable);
			return new FairPlaySignature (decode_base64 (result, "signature"),
				decode_base64 (result, "certificate_chain"));
		}

		public async ValidationData produce_validation_data (Cancellable? cancellable = null) throws Efni.Error, IOError {
			Gee.Map<string, string> bag = yield fetch_bag (cancellable);

			Json.Object step = yield send (new Soup.Message ("POST", @"$base_url/validation/begin"), cancellable);
			while (!step.get_boolean_member ("done"))
				step = yield exchange_validation (bag, step.get_object_member ("request"), cancellable);

			return new ValidationData (decode_base64 (step, "validation_data"),
				step.get_string_member ("valid_until"));
		}

		public async Gee.Map<string, string> fetch_anisette (Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			Json.Object obj = yield send (new Soup.Message ("GET", @"$base_url/anisette"), cancellable);

			var result = new Gee.HashMap<string, string> ();
			foreach (unowned string name in obj.get_members ())
				result[name] = node_to_string (obj.get_member (name));
			return result;
		}

		private static string node_to_string (Json.Node node) {
			if (node.get_value_type () == typeof (int64))
				return node.get_int ().to_string ();
			return node.get_string ();
		}

		private async Gee.Map<string, string> fetch_bag (Cancellable? cancellable) throws Efni.Error, IOError {
			var message = new Soup.Message ("GET",
				"https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3");
			Bytes response;
			try {
				response = yield session.send_and_read_async (message, Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to fetch the validation bag: %s", e.message);
			}

			var urls = new Gee.HashMap<string, string> ();
			try {
				var envelope = new Plist.from_data (response.get_data ());
				var bag = new Plist.from_data (envelope.get_bytes ("bag").get_data ());
				foreach (string key in bag.keys) {
					try {
						urls[key] = bag.get_string (key);
					} catch (PlistError e) {
					}
				}
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed validation bag: %s", e.message);
			}
			return urls;
		}

		private async Json.Object exchange_validation (Gee.Map<string, string> bag, Json.Object request,
				Cancellable? cancellable) throws Efni.Error, IOError {
			unowned string bag_key = request.get_string_member ("bag_key");
			string? url = bag[bag_key];
			if (url == null)
				throw new Efni.Error.PROTOCOL ("Unknown validation bag key: %s", bag_key);

			var message = new Soup.Message (request.get_string_member ("method"), url);
			Json.Object headers = request.get_object_member ("headers");
			unowned string? content_type = headers.has_member ("Content-Type")
				? headers.get_string_member ("Content-Type")
				: null;
			foreach (unowned string name in headers.get_members ()) {
				if (name != "Content-Type")
					message.get_request_headers ().append (name, headers.get_string_member (name));
			}
			if (request.has_member ("body")) {
				var body = new Bytes.take (Base64.decode (request.get_string_member ("body")));
				message.set_request_body_from_bytes (content_type, body);
			}

			Bytes response;
			try {
				response = yield session.send_and_read_async (message, Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Validation request to Apple failed: %s", e.message);
			}

			return yield continue_validation (message.status_code, response, cancellable);
		}

		private async Json.Object continue_validation (uint status, Bytes response, Cancellable? cancellable)
				throws Efni.Error, IOError {
			var builder = new Json.Builder ();
			builder.begin_object ();
			builder.set_member_name ("status");
			builder.add_int_value (status);
			builder.set_member_name ("body");
			builder.add_string_value (Base64.encode (response.get_data ()));
			builder.end_object ();

			var generator = new Json.Generator ();
			generator.set_root (builder.get_root ());

			var message = new Soup.Message ("POST", @"$base_url/validation/continue");
			message.set_request_body_from_bytes ("application/json", new Bytes (generator.to_data (null).data));
			return yield send (message, cancellable);
		}

		private async Json.Object send (Soup.Message message, Cancellable? cancellable) throws Efni.Error, IOError {
			Bytes response;
			try {
				response = yield session.send_and_read_async (message, Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to reach the identity oracle: %s", e.message);
			}

			if (message.status_code != 200)
				throw new Efni.Error.PROTOCOL ("Identity oracle returned HTTP %u", message.status_code);

			try {
				var parser = new Json.Parser ();
				parser.load_from_data ((string) response.get_data (), (ssize_t) response.get_size ());
				return parser.get_root ().get_object ();
			} catch (GLib.Error e) {
				throw new Efni.Error.PROTOCOL ("Malformed identity oracle response: %s", e.message);
			}
		}

		private static Bytes decode_base64 (Json.Object obj, string member) {
			return new Bytes.take (Base64.decode (obj.get_string_member (member)));
		}
	}

	/**
	 * The hardware and software identity a FairPlay signature is bound to, plus the
	 * User-Agent the device's push daemon presents, so Idun's activation request is
	 * indistinguishable from the real one.
	 */
	public sealed class DeviceIdentity : Object {
		public string serial_number {
			get;
			construct;
		}

		public string unique_device_id {
			get;
			construct;
		}

		public string hardware_version {
			get;
			construct;
		}

		public string software_name {
			get;
			construct;
		}

		public string software_version {
			get;
			construct;
		}

		public string software_build_id {
			get;
			construct;
		}

		public string push_user_agent {
			get;
			construct;
		}

		internal DeviceIdentity (Json.Object obj) {
			Object (
				serial_number: obj.get_string_member ("serial_number"),
				unique_device_id: obj.get_string_member ("unique_device_id"),
				hardware_version: obj.get_string_member ("hardware_version"),
				software_name: obj.get_string_member ("software_name"),
				software_version: obj.get_string_member ("software_version"),
				software_build_id: obj.get_string_member ("software_build_id"),
				push_user_agent: obj.get_string_member ("push_user_agent")
			);
		}
	}

	public sealed class FairPlaySignature : Object {
		public Bytes signature {
			get;
			construct;
		}

		public Bytes certificate_chain {
			get;
			construct;
		}

		public FairPlaySignature (Bytes signature, Bytes certificate_chain) {
			Object (signature: signature, certificate_chain: certificate_chain);
		}
	}

	public sealed class ValidationData : Object {
		public Bytes data {
			get;
			construct;
		}

		public string valid_until {
			get;
			construct;
		}

		public ValidationData (Bytes data, string valid_until) {
			Object (data: data, valid_until: valid_until);
		}
	}
}
