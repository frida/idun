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

		public ApnsIdentityStore? store {
			get;
			construct;
		}

		private Soup.Session session = new Soup.Session ();

		private const string ACTIVATION_URL =
			"https://albert.apple.com/deviceservices/deviceActivation?device=MacOS";

		public ApnsActivation (IdentityOracle oracle, ApnsIdentityStore? store = null) {
			Object (oracle: oracle, store: store);
		}

		public async ApnsIdentity activate (Cancellable? cancellable = null) throws Efni.Error, IOError {
			if (store != null) {
				ApnsIdentity? cached = store.load ();
				if (cached != null)
					return cached;
			}

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

			var identity = new ApnsIdentity (parse_certificate (response), private_key_pem);
			if (store != null)
				store.save (identity);
			return identity;
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

	/**
	 * Persists a push identity so activation survives across runs: a push
	 * certificate is long-lived, so there is no reason to re-provision one with
	 * Apple every time. The identity holds a private key, so it is written with
	 * the same owner-only permissions as the pairing store.
	 */
	public sealed class ApnsIdentityStore {
		public ApnsIdentity? load () {
			try {
				var plist = new Plist.from_data (query_location ().load_bytes ().get_data ());
				return new ApnsIdentity (plist.get_bytes ("pushCertificate"), plist.get_bytes ("privateKey"));
			} catch (GLib.Error e) {
				return null;
			}
		}

		public void save (ApnsIdentity identity) throws Efni.Error {
			var plist = new Plist ();
			plist.set_bytes ("pushCertificate", identity.push_certificate);
			plist.set_bytes ("privateKey", identity.private_key);

			File location = query_location ();
			try {
				location.get_parent ().make_directory_with_parents ();
			} catch (GLib.Error e) {
			}
			try {
				location.replace_contents (plist.to_binary (), null, false, PRIVATE | REPLACE_DESTINATION, null);
			} catch (GLib.Error e) {
				throw new Efni.Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		private static File query_location () {
			return File.new_build_filename (Environment.get_user_config_dir (), "idun", "apns-identity.plist");
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
