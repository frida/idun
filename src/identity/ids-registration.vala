using Efni;

namespace Idun {
	/**
	 * Registers Idun as a FaceTime endpoint under the account's handle: it advertises
	 * the messaging identity and the call capabilities that make a caller ring this
	 * device, signing the request with both the push and the IDS authentication
	 * identities the way the identity services require.
	 */
	public sealed class IdsRegistration : Object {
		public IdentityOracle oracle {
			get;
			construct;
		}

		private Soup.Session session = new Soup.Session ();
		private AppleTrust trust = new AppleTrust ();

		private const string REGISTER_KEY = "id-register";
		private const uint32 NGM_VERSION = 13;
		private const uint32 KT_VERSION = 5;
		private const uint32 TETRA_VERSION = 15;
		private const string SERVICE = "com.apple.private.alloy.facetime.multi";
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

		public IdsRegistration (IdentityOracle oracle) {
			Object (oracle: oracle);
		}

		construct {
			trust.guard (session);
		}

		public async RegisteredService register (IdsIdentity auth, ApnsIdentity push, Bytes push_token,
				MessageIdentity message, string handle, NgmIdentity? ngm = null,
				Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			Gee.Map<string, string> anisette = yield oracle.fetch_anisette (cancellable);
			ValidationData validation = yield oracle.produce_validation_data (cancellable);
			IdsBag bag = yield IdsBag.fetch (session, cancellable);

			Bytes body = gzip (build_request (auth.profile_id, handle, message, ngm, validation));
			uint8[] token = push_token.get_data ();

			var request = new Soup.Message ("POST", bag.lookup (REGISTER_KEY));
			apply_headers (request, anisette, push_token);
			sign (request, "push", null, null, push.private_key, certificate_der (push.push_certificate),
				body.get_data (), token);
			sign (request, "auth", "-0", auth.profile_id, auth.private_key, auth.certificate, body.get_data (), token);
			request.set_request_body_from_bytes ("application/x-apple-plist", body);

			Bytes response = yield send (request, cancellable);
			return parse_result (response, handle);
		}

		private static void apply_headers (Soup.Message message, Gee.Map<string, string> anisette, Bytes push_token) {
			var headers = message.request_headers;
			headers.replace ("x-push-token", Base64.encode (push_token.get_data ()));
			headers.replace ("x-protocol-version", PROTOCOL_VERSION);
			headers.replace ("Content-Encoding", "gzip");
			headers.replace ("Accept", "*/*");
			headers.replace ("User-Agent", USER_AGENT);
			headers.replace ("X-Apple-I-Client-Time", current_timestamp ());
			headers.replace ("X-Apple-Locale", "en_US");
			headers.replace ("X-Apple-I-TimeZone", "UTC");
			foreach (unowned string name in ANISETTE_HEADERS)
				headers.replace (name, anisette[name]);
		}

		private static Bytes build_request (string profile_id, string handle, MessageIdentity message,
				NgmIdentity? ngm, ValidationData validation) throws Efni.Error {
			var capability = new PlistDict ();
			capability.set_integer ("flags", 1);
			capability.set_string ("name", "Invitation");
			capability.set_integer ("version", 1);
			var capabilities = new PlistArray ();
			capabilities.add_dict (capability);

			var uri = new PlistDict ();
			uri.set_string ("uri", handle);
			var uris = new PlistArray ();
			uris.add_dict (uri);

			var user = new PlistDict ();
			user.set_dict ("client-data", build_client_data (message, ngm));
			user.set_array ("uris", uris);
			user.set_string ("user-id", profile_id);
			var users = new PlistArray ();
			users.add_dict (user);

			var service = new PlistDict ();
			service.set_array ("capabilities", capabilities);
			service.set_string ("service", SERVICE);
			service.set_array ("sub-services", new PlistArray ());
			service.set_array ("users", users);
			var services = new PlistArray ();
			services.add_dict (service);

			var request = new Plist ();
			request.set_string ("device-name", "idun");
			request.set_string ("hardware-version", "Mac17,2");
			request.set_string ("language", "en-US");
			request.set_string ("os-version", "macOS,27.0,26A428");
			request.set_string ("software-version", "26A428");
			request.set_bytes ("validation-data", validation.data);
			request.set_array ("services", services);
			return new Bytes (request.to_xml ().data);
		}

		private static PlistDict build_client_data (MessageIdentity message, NgmIdentity? ngm)
				throws Efni.Error {
			var data = new PlistDict ();
			data.set_bytes ("public-message-identity-key", message.public_key);
			data.set_integer ("public-message-identity-version", 2);
			data.set_integer ("ec-version", 1);
			data.set_boolean ("show-peer-errors", true);
			data.set_boolean ("supports-avless", true);
			data.set_boolean ("supports-co", true);
			data.set_boolean ("supports-gft-calls", true);
			data.set_boolean ("supports-gft-errors", true);
			data.set_boolean ("supports-modern-gft", true);
			data.set_boolean ("supports-self-one-to-one-invites", true);
			data.set_integer ("kt-version", 5);
			data.set_integer ("prefers-sdr", 0);
			data.set_boolean ("supports-animoji-v2", true);
			data.set_boolean ("supports-calls-25", true);
			data.set_boolean ("supports-hdr", true);
			data.set_boolean ("supports-heif", true);
			data.set_boolean ("supports-hi-res-vid", true);
			data.set_boolean ("supports-live-delivery", true);
			data.set_boolean ("supports-live-translation", true);
			data.set_boolean ("supports-qta", true);
			data.set_boolean ("supports-ssrc", true);
			data.set_boolean ("supports-uriless-membership-updates", true);

			if (ngm != null) {
				double timestamp = (double) get_real_time () / 1000000.0;
				data.set_bytes ("public-message-ngm-device-prekey-data-key",
					new Bytes (ngm.device_prekey_data (timestamp, TETRA_VERSION)));
				data.set_integer ("public-message-identity-ngm-version", NGM_VERSION);
				data.set_bytes ("kt-loggable-data",
					new Bytes (ngm.kt_loggable_data (NGM_VERSION, KT_VERSION)));
			}

			return data;
		}

		private static void sign (Soup.Message message, string prefix, string? suffix, string? user_id,
				Bytes key_pem, Bytes certificate, uint8[] body, uint8[] token) throws Efni.Error {
			uint8[] nonce = make_nonce ();
			uint8[] signature = signed_nonce (key_pem, nonce, body, token);

			var headers = message.request_headers;
			string tail = (suffix != null) ? suffix : "";
			if (user_id != null)
				headers.replace (@"x-$prefix-user-id$tail", user_id);
			headers.replace (@"x-$prefix-nonce$tail", Base64.encode (nonce));
			headers.replace (@"x-$prefix-sig$tail", Base64.encode (signature));
			headers.replace (@"x-$prefix-cert$tail", Base64.encode (certificate.get_data ()));
		}

		private static uint8[] signed_nonce (Bytes key_pem, uint8[] nonce, uint8[] body, uint8[] token)
				throws Efni.Error {
			uint8[] raw = rsa_sha1 (key_pem, signing_payload (nonce, body, token));
			var signature = new uint8[2 + raw.length];
			signature[0] = 0x01;
			signature[1] = 0x01;
			Memory.copy ((uint8*) signature + 2, raw, raw.length);
			return signature;
		}

		private static uint8[] signing_payload (uint8[] nonce, uint8[] body, uint8[] token) {
			var payload = new ByteArray ();
			payload.append (nonce);
			append_field (payload, REGISTER_KEY.data);
			append_field (payload, new uint8[0]);
			append_field (payload, body);
			append_field (payload, token);
			return payload.data;
		}

		private static void append_field (ByteArray payload, uint8[] field) {
			uint32 length = field.length;
			payload.append ({ (uint8) (length >> 24), (uint8) (length >> 16), (uint8) (length >> 8), (uint8) length });
			payload.append (field);
		}

		private static uint8[] make_nonce () {
			int64 now_ms = get_real_time () / 1000;
			var nonce = new uint8[17];
			nonce[0] = 0x01;
			for (int i = 0; i != 8; i++)
				nonce[1 + i] = (uint8) (now_ms >> ((7 - i) * 8));
			uint8[] random = new uint8[8];
			OpenSSL.Rng.generate (random);
			Memory.copy ((uint8*) nonce + 9, random, random.length);
			return nonce;
		}

		private static uint8[] rsa_sha1 (Bytes key_pem, uint8[] data) {
			var source = new OpenSSL.BasicIO.from_static_memory_buffer (key_pem.get_data ());
			OpenSSL.Envelope.Key? key = new OpenSSL.Envelope.Key.from_private_key_pem (source);

			var ctx = new OpenSSL.Envelope.MessageDigestContext ();
			ctx.digest_sign_init (null, OpenSSL.Envelope.MessageDigest.fetch (null, "SHA1"), null, key);
			size_t length = 0;
			ctx.digest_sign (null, ref length, data);
			var signature = new uint8[length];
			ctx.digest_sign (signature, ref length, data);
			signature.length = (int) length;
			return signature;
		}

		private static Bytes certificate_der (Bytes pem) {
			var source = new OpenSSL.BasicIO.from_static_memory_buffer (pem.get_data ());
			var certificate = new OpenSSL.X509.from_pem (source);
			var sink = new OpenSSL.BasicIO (OpenSSL.BasicIOMethod.memory ());
			certificate.to_der (sink);
			unowned uint8[] data;
			long size = sink.get_mem_data (out data);
			data.length = (int) size;
			return new Bytes (data);
		}

		private static RegisteredService parse_result (Bytes response, string handle) throws Efni.Error {
			try {
				var plist = new Plist.from_data (response.get_data ());
				int64 status = plist.get_integer ("status");
				if (status != 0) {
					throw new Efni.Error.PROTOCOL ("IDS registration failed with status %" +
						int64.FORMAT_MODIFIER + "d", status);
				}

				PlistDict user = plist.get_array ("services").get_dict (0).get_array ("users").get_dict (0);
				int64 user_status = user.get_integer ("status");
				if (user_status != 0) {
					throw new Efni.Error.PROTOCOL ("IDS registration rejected the handle with status %" +
						int64.FORMAT_MODIFIER + "d", user_status);
				}

				Bytes? certificate = user.has ("cert") ? user.get_bytes ("cert") : null;
				return new RegisteredService (handle, certificate);
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed IDS registration response: %s", e.message);
			}
		}

		private async Bytes send (Soup.Message message, Cancellable? cancellable) throws Efni.Error, IOError {
			try {
				Bytes response = yield session.send_and_read_async (message, Priority.DEFAULT, cancellable);
				if (message.status_code != 200)
					throw new Efni.Error.PROTOCOL ("IDS registration returned HTTP %u", message.status_code);
				return response;
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to reach the IDS registration endpoint: %s", e.message);
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
				throw new Efni.Error.PROTOCOL ("Unable to compress IDS registration request: %s", e.message);
			}
		}

		private static string current_timestamp () {
			return new DateTime.now_utc ().format ("%Y-%m-%dT%H:%M:%SZ");
		}
	}

	public sealed class RegisteredService : Object {
		public string handle {
			get;
			construct;
		}

		public Bytes? certificate {
			get;
			construct;
		}

		public RegisteredService (string handle, Bytes? certificate) {
			Object (handle: handle, certificate: certificate);
		}
	}
}
