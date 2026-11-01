using Efni;

namespace Idun {
	/**
	 * A client for Apple's escrow proxy: the REST service that holds the account's escrow
	 * records and hands back the bottled entropy once the caller proves knowledge of the
	 * iCloud Security Code over SRP-6a. Idun lists the records, runs the SRP handshake with
	 * the iCSC, and recovers the record whose entropy opens an Octagon bottle. Every request
	 * carries the account's MobileMe auth token.
	 */
	public sealed class EscrowProxyClient : Object {
		public string base_url {
			get;
			construct;
		}

		public string apple_id {
			get;
			construct;
		}

		public string auth_token {
			get;
			construct;
		}

		public string device_id {
			get;
			set;
			default = "";
		}

		public string client_info {
			get;
			set;
			default = "<Mac17,2> <macOS;27.0;26A428> <com.apple.AuthKit/1 (com.apple.sbd/747.0.6)>";
		}

		/**
		 * Anisette one-time machine headers (X-Apple-I-MD, X-Apple-I-MD-M, X-Apple-I-MD-RINFO).
		 * The escrow proxy validates the PET together with these, so they must accompany every
		 * authenticated request.
		 */
		public Gee.Map<string, string> anisette_headers {
			get;
			set;
			default = new Gee.HashMap<string, string> ();
		}

		private Soup.Session session = new Soup.Session ();
		private Soup.Logger? logger = null;
		private string device_session_id = Uuid.string_random ().up ();
		private OpenSSL.BigNumber srp_private;
		private OpenSSL.BigNumber srp_public;

		private const string USER_AGENT = "com.apple.sbd/747.0.6 CFNetwork/3896.100.1.1.1 Darwin/27.0.0";
		private const string RECORD_LABEL = "com.apple.securebackup.record";
		private const string ICDP_RECORD_LABEL = "com.apple.icdp.record";
		private const string USER_ACTION_LABEL = "idun: escrow recovery";
		private const string CONTENT_TYPE = "application/x-apple-plist";
		private const string N_HEX =
			"AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
			"A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
			"E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
			"55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
			"CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
			"544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
			"AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
			"94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

		public EscrowProxyClient (string base_url, string apple_id, string auth_token) {
			Object (base_url: base_url, apple_id: apple_id, auth_token: auth_token);
		}

		/**
		 * Fetch the account's escrow records.
		 */
		public async Plist get_records (Cancellable? cancellable = null) throws Efni.Error, IOError {
			var body = new Plist ();
			body.set_string ("command", "GETRECORDS");
			body.set_string ("label", RECORD_LABEL);
			body.set_string ("transactionUUID", Uuid.string_random ().up ());
			body.set_string ("userActionLabel", USER_ACTION_LABEL);
			body.set_integer ("version", 1);

			return yield post ("get_records", body, true, cancellable);
		}

		/**
		 * Begin the SRP-6a handshake for one record: generate the client ephemeral and post it,
		 * returning the server's challenge (its ephemeral, the salt, and the password metadata
		 * that parameterises the key derivation).
		 */
		/**
		 * Fetch the escrow club certificate, the trust anchor the SRP recovery is bound to.
		 * This precedes the SRP handshake in the join flow.
		 */
		public async Plist get_club_cert (Cancellable? cancellable = null) throws Efni.Error, IOError {
			var versions = new PlistArray ();
			versions.add_integer (101);
			versions.add_integer (500);
			versions.add_integer (103);
			versions.add_integer (102);

			var body = new Plist ();
			body.set_string ("command", "GETCLUB");
			body.set_string ("label", ICDP_RECORD_LABEL);
			body.set_string ("transactionUUID", Uuid.string_random ().up ());
			body.set_array ("trustedRootCertVersions", versions);
			body.set_string ("userActionLabel", USER_ACTION_LABEL);
			body.set_integer ("version", 1);

			return yield post ("get_club_cert", body, true, cancellable);
		}

		public async Plist srp_init (string record_id, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			var ctx = new OpenSSL.BigNumberContext.secure ();
			var n = bn_from (decode_hex (N_HEX));
			var g = bn_from ({ 2 });

			var secret = new uint8[32];
			OpenSSL.Rng.generate (secret);
			srp_private = bn_from (secret);
			srp_public = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mod_exp (srp_public, g, srp_private, n, ctx);

			var body = new Plist ();
			body.set_string ("command", "SRP_INIT");
			body.set_string ("blob", Base64.encode (bn_to_padded (srp_public)));
			body.set_string ("label", ICDP_RECORD_LABEL + "." + record_id);
			body.set_string ("transactionUUID", Uuid.string_random ().up ());
			body.set_string ("userActionLabel", USER_ACTION_LABEL);
			body.set_integer ("version", 1);

			return yield post ("srp_init", body, true, cancellable);
		}

		/**
		 * Run the full escrow SRP recovery for one record and return its bottled entropy — the
		 * seed that regenerates the account's Octagon peer keys.
		 *
		 * This is IRREVERSIBLE: the escrow proxy allows only ten authentication attempts per record
		 * and the HSM cluster destroys the record on the tenth failure, so a wrong secret spends a
		 * precious attempt. The caller must pass a secret it is confident in and set {@link confirm}.
		 */
		public async Bytes recover (string record_label, uint8[] secret, bool confirm,
				Cancellable? cancellable = null) throws Efni.Error, IOError {
			if (!confirm)
				throw new Efni.Error.NOT_SUPPORTED (
					"Escrow recovery is irreversible (ten attempts, then the record is destroyed); " +
					"pass confirm only after the secret is verified");

			string label = record_label;
			string txn = Uuid.string_random ().up ();
			var srp = new EscrowSrpSession ();

			var init_body = new Plist ();
			init_body.set_string ("command", "SRP_INIT");
			init_body.set_string ("blob", Base64.encode (srp.public_a ()));
			init_body.set_string ("label", label);
			init_body.set_string ("transactionUUID", txn);
			init_body.set_string ("userActionLabel", USER_ACTION_LABEL);
			init_body.set_integer ("version", 1);
			Plist init = yield post ("srp_init", init_body, true, cancellable);

			string dsid = init.get_string ("dsid");
			int club_type_id = has_integer (init, "clubTypeID") ? (int) init.get_integer ("clubTypeID") : 0;

			uint8[] header;
			Bytes[] sections = EscrowKeyVault.unpack (Base64.decode (init.get_string ("respBlob")),
				24, 3, out header);
			uint8[] id_section = sections[0].get_data ();
			uint8[] salt = sections[1].get_data ();
			uint8[] server_public = sections[2].get_data ();

			srp.process (dsid.data, secret, salt, server_public);

			int version = (club_type_id == 1) ? 2 : 0;
			header[0] = 0; header[1] = 0; header[2] = 0; header[3] = (uint8) 165;
			header[4] = 0; header[5] = 0; header[6] = 0; header[7] = (uint8) version;
			var proof = new EscrowKeyVault (header);
			proof.add_section_padded (id_section, 20);
			proof.add_section (srp.client_proof);

			var recover_body = new Plist ();
			recover_body.set_string ("command", "RECOVER");
			recover_body.set_string ("blob", Base64.encode (proof.pack ()));
			recover_body.set_string ("label", label);
			recover_body.set_string ("transactionUUID", txn);
			recover_body.set_string ("userActionLabel", USER_ACTION_LABEL);
			recover_body.set_integer ("version", 1);
			Plist recovered = yield post ("recover", recover_body, true, cancellable);

			return decrypt_recovered_record (srp.shared_key, srp.server_proof (), club_type_id,
				Base64.decode (recovered.get_string ("respBlob")), secret);
		}

		/**
		 * Verify the server proof carried in a RECOVER response and decrypt the record it wraps
		 * down to the bottled entropy. Split out from the live flow so the SRP-to-bottle crypto
		 * can be exercised offline against a simulated server before an irreversible attempt.
		 */
		public static Bytes decrypt_recovered_record (uint8[] shared_key, uint8[] expected_proof,
				int club_type_id, uint8[] response_blob, uint8[] secret) throws Efni.Error {
			uint8[] response_header;
			Bytes[] payloads = EscrowKeyVault.unpack (response_blob,
				(club_type_id == 1) ? 40 : 24, 3, out response_header);

			uint8[] server_proof = payloads[0].get_data ();
			if (expected_proof.length != server_proof.length ||
					Memory.cmp (expected_proof, server_proof, expected_proof.length) != 0)
				throw new Efni.Error.PROTOCOL ("Escrow proxy server proof mismatch");

			uint32 record_version = EscrowKeyVault.read_be32 (response_header, 4);
			uint8[] nonce = payloads[1].get_data ();
			uint8[] ciphertext = payloads[2].get_data ();
			uint8[] inner;
			if (record_version == 0) {
				inner = OctagonCrypto.aes_cbc_decrypt (shared_key, nonce, ciphertext);
			} else if (record_version == 2) {
				int split = ciphertext.length - 16;
				inner = OctagonCrypto.aes_256_gcm_decrypt (shared_key, nonce,
					ciphertext[0 : split], ciphertext[split : ciphertext.length]);
			} else {
				throw new Efni.Error.PROTOCOL ("Unsupported escrow record version %u", record_version);
			}

			return unwrap_bottle (inner, secret);
		}

		private static Bytes unwrap_bottle (uint8[] inner, uint8[] secret) throws Efni.Error {
			uint8[] inner_header;
			Bytes[] parts = EscrowKeyVault.unpack (inner, 16, 6, out inner_header);

			int rounds = (int) EscrowKeyVault.read_be32 (inner_header, 8);
			uint8[] salt = parts[1].get_data ();
			uint8[] derived = OctagonCrypto.pbkdf2_sha256 (secret, salt, rounds, 16);
			uint8[] bottle_plist = OctagonCrypto.aes_cbc_decrypt (derived, salt[0 : 16],
				parts[3].get_data ());

			try {
				var bottle = new Plist.from_data (bottle_plist);
				return bottle.get_bytes ("BottledPeerEntropy");
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed escrow bottle: %s", e.message);
			}
		}

		private static bool has_integer (Plist plist, string key) {
			try {
				plist.get_integer (key);
				return true;
			} catch (PlistError e) {
				return false;
			}
		}

		private async Plist post (string endpoint, Plist body, bool authenticated, Cancellable? cancellable)
				throws Efni.Error, IOError {
			if (Environment.get_variable ("IDUN_ESCROW_DUMP_REQ") != null && logger == null) {
				logger = new Soup.Logger (Soup.LoggerLogLevel.HEADERS);
				session.add_feature (logger);
			}

			var message = new Soup.Message ("POST", base_url + "/escrowproxy/api/" + endpoint);
			var headers = message.request_headers;
			headers.replace ("Content-Type", CONTENT_TYPE);
			headers.replace ("User-Agent", USER_AGENT);
			headers.replace ("Accept", "*/*");
			headers.replace ("Accept-Encoding", "gzip, deflate, br");
			headers.replace ("Accept-Language", "en-US,en;q=0.9");
			headers.replace ("X-Mme-Device-Id", (device_id != "") ? device_id : Uuid.string_random ().up ());
			headers.replace ("X-MMe-Client-Info", client_info);
			headers.replace ("X-Apple-I-Device-Session-Id", device_session_id);
			headers.replace ("X-Apple-I-Flow-Id", Uuid.string_random ().up ());
			if (authenticated) {
				headers.replace ("Authorization", "Basic " +
					Base64.encode (@"$apple_id:$auth_token".data));
				foreach (var entry in anisette_headers.entries)
					headers.replace (entry.key, entry.value);
			}
			message.set_request_body_from_bytes (CONTENT_TYPE, new Bytes (body.to_xml ().data));

			try {
				Bytes response = yield session.send_and_read_async (message, Priority.DEFAULT, cancellable);
				if (message.status_code != 200) {
					string snippet = ((string) response.get_data ()).substring (0, int.min (400, response.length));
					throw new Efni.Error.PROTOCOL ("Escrow proxy %s returned HTTP %u: %s",
						endpoint, message.status_code, snippet);
				}
				return new Plist.from_data (response.get_data ());
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed escrow proxy %s response: %s", endpoint, e.message);
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to reach the escrow proxy: %s", e.message);
			}
		}

		private static OpenSSL.BigNumber bn_from (uint8[] data) {
			return new OpenSSL.BigNumber.from_big_endian (data);
		}

		private static uint8[] bn_to_padded (OpenSSL.BigNumber value) {
			var buffer = new uint8[256];
			value.to_big_endian_padded (buffer);
			return buffer;
		}

		private static uint8[] decode_hex (string hex) {
			var bytes = new uint8[hex.length / 2];
			for (int i = 0; i != bytes.length; i++)
				bytes[i] = (uint8) hex.substring (i * 2, 2).to_long (null, 16);
			return bytes;
		}
	}
}
