using Efni;

namespace Idun {
	/**
	 * Obtains the IDS authentication certificate: Idun generates an RSA identity key
	 * and sends a certificate request to Apple, signed for the delegate's profile, and
	 * receives the certificate that lets it sign registration and lookup requests.
	 */
	public sealed class IdsAuthCert : Object {
		public IdentityOracle oracle {
			get;
			construct;
		}

		private Soup.Session session = new Soup.Session ();
		private AppleTrust trust = new AppleTrust ();

		private const string USER_AGENT = "com.apple.invitation-registration [macOS,27.0,26A428,Mac17,2]";
		private const string PROTOCOL_VERSION = "1640";

		private const string[] ANISETTE_HEADERS = {
			"X-MMe-Client-Info",
			"X-Apple-I-MD",
			"X-Apple-I-MD-M",
			"X-Apple-I-MD-RINFO",
			"X-Apple-I-MD-LU",
			"X-Apple-I-SRL-NO",
			"X-Mme-Device-Id",
		};

		public IdsAuthCert (IdentityOracle oracle) {
			Object (oracle: oracle);
		}

		construct {
			trust.guard (session);
		}

		public async IdsIdentity authenticate (IdsDelegate delegation, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			Gee.Map<string, string> anisette = yield oracle.fetch_anisette (cancellable);
			IdsBag bag = yield IdsBag.fetch (session, cancellable);

			OpenSSL.Envelope.Key key = generate_key ();
			Bytes certificate_request = build_certificate_request (key, delegation.profile_id);

			var message = new Soup.Message ("POST", bag.lookup ("id-authenticate-ds-id"));
			apply_headers (message, anisette);
			message.set_request_body_from_bytes ("application/x-apple-plist",
				gzip (build_request (delegation, certificate_request)));

			Bytes response = yield send (message, cancellable);
			return parse_identity (response, delegation.profile_id, key);
		}

		private static void apply_headers (Soup.Message message, Gee.Map<string, string> anisette) {
			var headers = message.request_headers;
			headers.replace ("User-Agent", USER_AGENT);
			headers.replace ("x-protocol-version", PROTOCOL_VERSION);
			headers.replace ("Content-Encoding", "gzip");
			headers.replace ("Accept", "*/*");
			headers.replace ("X-Apple-I-Client-Time", current_timestamp ());
			headers.replace ("X-Apple-Locale", "en_US");
			headers.replace ("X-Apple-I-TimeZone", "UTC");
			foreach (unowned string name in ANISETTE_HEADERS)
				headers.replace (name, anisette[name]);
		}

		private static Bytes build_request (IdsDelegate delegation, Bytes certificate_request) {
			var authentication = new PlistDict ();
			authentication.set_string ("auth-token", delegation.auth_token);

			var request = new Plist ();
			request.set_dict ("authentication-data", authentication);
			request.set_bytes ("csr", certificate_request);
			request.set_string ("realm-user-id", delegation.profile_id);
			return new Bytes (request.to_xml ().data);
		}

		private static IdsIdentity parse_identity (Bytes response, string profile_id,
				OpenSSL.Envelope.Key key) throws Efni.Error {
			try {
				var plist = new Plist.from_data (response.get_data ());
				int64 status = plist.get_integer ("status");
				if (status != 0) {
					throw new Efni.Error.PROTOCOL ("IDS authentication failed with status %" +
						int64.FORMAT_MODIFIER + "d", status);
				}
				return new IdsIdentity (profile_id, plist.get_bytes ("cert"), export_private_key (key));
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed IDS authentication response: %s", e.message);
			}
		}

		private static OpenSSL.Envelope.Key generate_key () {
			var ctx = new OpenSSL.Envelope.KeyContext.for_key_type (OpenSSL.Envelope.KeyType.RSA);
			ctx.keygen_init ();
			ctx.set_rsa_keygen_bits (2048);
			OpenSSL.Envelope.Key? key = null;
			ctx.keygen (ref key);
			return key;
		}

		private static Bytes build_certificate_request (OpenSSL.Envelope.Key key, string profile_id) {
			var request = new OpenSSL.CertificateRequest ();
			request.set_version (0);
			request.get_subject_name ().add_entry_by_txt ("CN", OpenSSL.ASN1.MultiByteStringType.ASCII,
				common_name (profile_id).data);
			request.set_pubkey (key);
			request.sign (key, OpenSSL.Envelope.MessageDigest.fetch (null, "SHA1"));

			var sink = new OpenSSL.BasicIO (OpenSSL.BasicIOMethod.memory ());
			request.to_der (sink);
			return read_bio (sink);
		}

		private static string common_name (string profile_id) {
			return Checksum.compute_for_data (ChecksumType.SHA1, profile_id.data).up ();
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

		private async Bytes send (Soup.Message message, Cancellable? cancellable) throws Efni.Error, IOError {
			try {
				Bytes response = yield session.send_and_read_async (message, Priority.DEFAULT, cancellable);
				if (message.status_code != 200)
					throw new Efni.Error.PROTOCOL ("IDS authentication returned HTTP %u", message.status_code);
				return response;
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to reach the IDS authentication endpoint: %s", e.message);
			}
		}

		private static Bytes gzip (Bytes data) throws Efni.Error {
			try {
				var source = new ConverterInputStream (new MemoryInputStream.from_bytes (data),
					new ZlibCompressor (ZlibCompressorFormat.GZIP));
				var sink = new MemoryOutputStream.resizable ();
				sink.splice (source, OutputStreamSpliceFlags.CLOSE_SOURCE | OutputStreamSpliceFlags.CLOSE_TARGET);
				return sink.steal_as_bytes ();
			} catch (GLib.Error e) {
				throw new Efni.Error.PROTOCOL ("Unable to compress IDS authentication request: %s", e.message);
			}
		}

		private static string current_timestamp () {
			return new DateTime.now_utc ().format ("%Y-%m-%dT%H:%M:%SZ");
		}
	}

	public sealed class IdsIdentity : Object {
		public string profile_id {
			get;
			construct;
		}

		public Bytes certificate {
			get;
			construct;
		}

		public Bytes private_key {
			get;
			construct;
		}

		public IdsIdentity (string profile_id, Bytes certificate, Bytes private_key) {
			Object (profile_id: profile_id, certificate: certificate, private_key: private_key);
		}
	}

	/**
	 * Persists the IDS authentication identity so it survives across runs. Reusing it
	 * lets Idun skip the Grand Slam, delegate, and authentication-certificate exchanges
	 * entirely, which is both faster and avoids re-prompting for a two-factor code.
	 */
	public sealed class IdsIdentityStore : IdentityStore {
		public IdsIdentity? load () {
			Plist? plist = read ();
			if (plist == null)
				return null;
			try {
				return new IdsIdentity (plist.get_string ("profileId"), plist.get_bytes ("certificate"),
					plist.get_bytes ("privateKey"));
			} catch (PlistError e) {
				return null;
			}
		}

		public void save (IdsIdentity identity) throws Efni.Error {
			var plist = new Plist ();
			plist.set_string ("profileId", identity.profile_id);
			plist.set_bytes ("certificate", identity.certificate);
			plist.set_bytes ("privateKey", identity.private_key);
			write (plist);
		}

		protected override string filename () {
			return "ids-identity.plist";
		}
	}
}
