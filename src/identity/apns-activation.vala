using Efni;

namespace Idun {
	/**
	 * Activates a push identity with Apple, the first step toward talking to its
	 * push-based services. Idun generates its own key, has the identity oracle sign the
	 * activation the way a real device's push daemon would, and posts it to Apple's
	 * activation server itself, yielding the push certificate Idun then presents to
	 * the APNs courier.
	 */
	public sealed class ApnsActivation : Object {
		public IdentityOracle oracle {
			get;
			construct;
		}

		private Soup.Session session = new Soup.Session ();

		private const string ACTIVATION_URL =
			"https://albert.apple.com/deviceservices/deviceActivation?device=MacOS";

		public ApnsActivation (IdentityOracle oracle) {
			Object (oracle: oracle);
		}

		public async ApnsIdentity activate (Cancellable? cancellable = null) throws Efni.Error, IOError {
			DeviceIdentity device = yield oracle.fetch_device_info (cancellable);

			OpenSSL.Envelope.Key key = generate_key ();
			Bytes private_key_pem = export_private_key (key);

			Bytes activation_info = build_activation_info (device, build_certificate_request (key));
			FairPlaySignature signature = yield oracle.sign_activation (activation_info, cancellable);

			string form = "activation-info=" + Uri.escape_string (
				build_activation_request (activation_info, signature), null);

			var message = new Soup.Message ("POST", ACTIVATION_URL);
			message.get_request_headers ().append ("User-Agent", device.push_user_agent);
			message.set_request_body_from_bytes ("application/x-www-form-urlencoded", new Bytes (form.data));

			Bytes response;
			try {
				response = yield session.send_and_read_async (message, Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to reach the activation server: %s", e.message);
			}
			if (message.status_code != 200)
				throw new Efni.Error.PROTOCOL ("Activation server returned HTTP %u", message.status_code);

			return new ApnsIdentity (parse_certificate (response), private_key_pem);
		}

		private static Bytes build_activation_info (DeviceIdentity device, Bytes certificate_request) {
			var info = new Plist ();
			info.set_string ("ActivationRandomness", Uuid.string_random ().up ());
			info.set_string ("ActivationState", "Unactivated");
			info.set_string ("BuildVersion", device.software_build_id);
			info.set_bytes ("DeviceCertRequest", certificate_request);
			info.set_string ("DeviceClass", "MacOS");
			info.set_string ("ProductType", device.hardware_version);
			info.set_string ("ProductVersion", device.software_version);
			info.set_string ("SerialNumber", device.serial_number);
			info.set_string ("UniqueDeviceID", device.unique_device_id);
			return new Bytes (info.to_xml ().data);
		}

		private static string build_activation_request (Bytes activation_info, FairPlaySignature signature) {
			var request = new Plist ();
			request.set_boolean ("ActivationInfoComplete", true);
			request.set_bytes ("ActivationInfoXML", activation_info);
			request.set_bytes ("FairPlayCertChain", signature.certificate_chain);
			request.set_bytes ("FairPlaySignature", signature.signature);
			return request.to_xml ();
		}

		private static Bytes parse_certificate (Bytes response) throws Efni.Error {
			var document = new StringBuilder ();
			document.append_len ((string) response.get_data (), response.get_data ().length);

			const string OPEN = "<Protocol>";
			const string CLOSE = "</Protocol>";
			int start = document.str.index_of (OPEN);
			int end = document.str.index_of (CLOSE);
			if (start == -1 || end == -1)
				throw new Efni.Error.PROTOCOL ("Activation response carried no protocol record");

			try {
				start += OPEN.length;
				var record = new Plist.from_xml (document.str[start:end]);
				return record
					.get_dict ("device-activation")
					.get_dict ("activation-record")
					.get_bytes ("DeviceCertificate");
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed activation record: %s", e.message);
			}
		}

		private static OpenSSL.Envelope.Key generate_key () {
			var ctx = new OpenSSL.Envelope.KeyContext.for_key_type (OpenSSL.Envelope.KeyType.RSA);
			ctx.keygen_init ();
			ctx.set_rsa_keygen_bits (1024);
			OpenSSL.Envelope.Key? key = null;
			ctx.keygen (ref key);
			return key;
		}

		private static Bytes build_certificate_request (OpenSSL.Envelope.Key key) {
			var request = new OpenSSL.CertificateRequest ();
			request.set_version (0);
			request.get_subject_name ().add_entry_by_txt ("CN", OpenSSL.ASN1.MultiByteStringType.ASCII,
				"Client Push Certificate".data);
			request.set_pubkey (key);
			request.sign (key, OpenSSL.Envelope.MessageDigest.fetch (null, "SHA1"));

			var sink = new OpenSSL.BasicIO (OpenSSL.BasicIOMethod.memory ());
			request.to_pem (sink);
			return read_bio (sink);
		}

		private static Bytes export_private_key (OpenSSL.Envelope.Key key) {
			var sink = new OpenSSL.BasicIO (OpenSSL.BasicIOMethod.memory ());
			OpenSSL.Envelope.write_private_key_pem (sink, key);
			return read_bio (sink);
		}

		private static Bytes read_bio (OpenSSL.BasicIO bio) {
			unowned uint8[] data;
			long size = bio.get_mem_data (out data);
			data.length = (int) size;
			return new Bytes (data);
		}
	}

	public sealed class ApnsIdentity : Object {
		public Bytes push_certificate {
			get;
			construct;
		}

		public Bytes private_key {
			get;
			construct;
		}

		public ApnsIdentity (Bytes push_certificate, Bytes private_key) {
			Object (push_certificate: push_certificate, private_key: private_key);
		}
	}
}
