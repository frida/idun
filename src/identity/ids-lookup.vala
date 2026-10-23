using Efni;

namespace Idun {
	/**
	 * Looks a handle up in the identity services: given a peer's URI it returns the
	 * push tokens and messaging identity keys the peer registered, which is what Idun
	 * needs to address and seal pair-encrypted signaling back to them.
	 */
	public sealed class IdsLookup : Object {
		public IdentityOracle oracle {
			get;
			construct;
		}

		private Soup.Session session = new Soup.Session ();
		private AppleTrust trust = new AppleTrust ();

		private const string QUERY_KEY = "id-query";
		private const string USER_AGENT = "com.apple.madrid-lookup [macOS,27.0,26A428,Mac17,2]";
		private const string PROTOCOL_VERSION = "27000000";

		private const string[] ANISETTE_HEADERS = {
			"X-MMe-Client-Info",
			"X-Apple-I-MD",
			"X-Apple-I-MD-M",
			"X-Apple-I-MD-RINFO",
			"X-Apple-I-MD-LU",
			"X-Apple-I-SRL-NO",
			"X-Mme-Device-Id",
		};

		public IdsLookup (IdentityOracle oracle) {
			Object (oracle: oracle);
		}

		construct {
			trust.guard (session);
		}

		public async Gee.Map<string, PeerIdentity> query (IdsIdentity identity, Bytes registration_certificate,
				Bytes push_token, string self_handle, string[] handles, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			Gee.Map<string, string> anisette = yield oracle.fetch_anisette (cancellable);
			Gee.Map<string, string> attestation = yield oracle.fetch_baa_headers (cancellable);
			IdsBag bag = yield IdsBag.fetch (session, cancellable);

			Bytes body = gzip (build_request (handles));
			uint8[] token = push_token.get_data ();

			var message = new Soup.Message ("POST", bag.lookup (QUERY_KEY));
			apply_headers (message, anisette, attestation, self_handle, push_token);
			sign (message, identity.profile_id, identity.private_key, registration_certificate, body.get_data (),
				token);
			message.set_request_body_from_bytes ("application/x-apple-plist", body);

			Bytes response = yield send (message, cancellable);
			return parse_results (response);
		}

		private static void apply_headers (Soup.Message message, Gee.Map<string, string> anisette,
				Gee.Map<string, string> attestation, string self_handle, Bytes push_token) {
			var headers = message.request_headers;
			headers.replace ("x-id-self-uri", self_handle);
			headers.replace ("x-push-token", Base64.encode (push_token.get_data ()));
			headers.replace ("x-protocol-version", PROTOCOL_VERSION);
			headers.replace ("x-apple-apns-dual-mode-delivery-type", "2");
			headers.replace ("x-apple-baa-header-source", "1");
			headers.replace ("Content-Encoding", "gzip");
			headers.replace ("Accept", "*/*");
			headers.replace ("User-Agent", USER_AGENT);
			headers.replace ("X-Apple-I-Client-Time", current_timestamp ());
			headers.replace ("X-Apple-Locale", "en_US");
			headers.replace ("X-Apple-I-TimeZone", "UTC");
			foreach (unowned string name in ANISETTE_HEADERS)
				headers.replace (name, anisette[name]);
			foreach (var entry in attestation.entries)
				headers.replace (entry.key, entry.value);
		}

		private static Bytes build_request (string[] handles) {
			var uris = new PlistArray ();
			foreach (unowned string handle in handles)
				uris.add_string (handle);

			var request = new Plist ();
			request.set_array ("uris", uris);
			return new Bytes (request.to_xml ().data);
		}

		private static void sign (Soup.Message message, string user_id, Bytes key_pem, Bytes certificate,
				uint8[] body, uint8[] token) throws Efni.Error {
			uint8[] nonce = make_nonce ();
			uint8[] raw = rsa_sha1 (key_pem, signing_payload (nonce, body, token));
			var signature = new uint8[2 + raw.length];
			signature[0] = 0x01;
			signature[1] = 0x01;
			Memory.copy ((uint8*) signature + 2, raw, raw.length);

			var headers = message.request_headers;
			headers.replace ("x-id-user-id", user_id);
			headers.replace ("x-id-nonce", Base64.encode (nonce));
			headers.replace ("x-id-sig", Base64.encode (signature));
			headers.replace ("x-id-cert", Base64.encode (certificate.get_data ()));
		}

		private static uint8[] signing_payload (uint8[] nonce, uint8[] body, uint8[] token) {
			var payload = new ByteArray ();
			payload.append (nonce);
			append_field (payload, QUERY_KEY.data);
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

		private static Gee.Map<string, PeerIdentity> parse_results (Bytes response) throws Efni.Error {
			var peers = new Gee.HashMap<string, PeerIdentity> ();
			try {
				var plist = new Plist.from_data (response.get_data ());
				int64 status = plist.get_integer ("status");
				if (status != 0) {
					throw new Efni.Error.PROTOCOL ("IDS lookup failed with status %" +
						int64.FORMAT_MODIFIER + "d", status);
				}

				PlistDict results = plist.get_dict ("results");
				foreach (string uri in results.keys) {
					PlistArray identities = results.get_dict (uri).get_array ("identities");
					for (int i = 0; i != identities.length; i++) {
						PlistDict identity = identities.get_dict (i);
						if (!identity.has ("client-data"))
							continue;
						PlistDict client_data = identity.get_dict ("client-data");
						if (!client_data.has ("public-message-identity-key"))
							continue;
						peers[uri] = new PeerIdentity (uri, identity.get_bytes ("push-token"),
							client_data.get_bytes ("public-message-identity-key"));
						break;
					}
				}
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed IDS lookup response: %s", e.message);
			}
			return peers;
		}

		private async Bytes send (Soup.Message message, Cancellable? cancellable) throws Efni.Error, IOError {
			try {
				Bytes response = yield session.send_and_read_async (message, Priority.DEFAULT, cancellable);
				if (message.status_code != 200)
					throw new Efni.Error.PROTOCOL ("IDS lookup returned HTTP %u", message.status_code);
				return response;
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to reach the IDS lookup endpoint: %s", e.message);
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
				throw new Efni.Error.PROTOCOL ("Unable to compress IDS lookup request: %s", e.message);
			}
		}

		private static string current_timestamp () {
			return new DateTime.now_utc ().format ("%Y-%m-%dT%H:%M:%SZ");
		}
	}

	public sealed class PeerIdentity : Object {
		public string uri {
			get;
			construct;
		}

		public Bytes push_token {
			get;
			construct;
		}

		public Bytes identity_key {
			get;
			construct;
		}

		public PeerIdentity (string uri, Bytes push_token, Bytes identity_key) {
			Object (uri: uri, push_token: push_token, identity_key: identity_key);
		}
	}
}
