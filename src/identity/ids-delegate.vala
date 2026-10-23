using Efni;

namespace Idun {
	/**
	 * Exchanges a Grand Slam PET for an IDS delegate authorization: the profile id
	 * and auth token that identify the account to the identity services. Idun makes
	 * the request itself and only asks the oracle for the anisette and validation
	 * data the login endpoint expects.
	 */
	public sealed class IdsDelegateAuth : Object {
		public IdentityOracle oracle {
			get;
			construct;
		}

		private Soup.Session session = new Soup.Session ();

		private const string LOGIN_URL = "https://setup.icloud.com/setup/signin/v2/login";
		private const string USER_AGENT = "com.apple.iCloudHelper/282 CFNetwork/1498.700.2 Darwin/23.6.0";

		private const string[] ANISETTE_HEADERS = {
			"X-Mme-Client-Info",
			"X-Apple-I-MD",
			"X-Apple-I-MD-M",
			"X-Apple-I-MD-RINFO",
			"X-Apple-I-MD-LU",
			"X-Apple-I-SRL-NO",
			"X-Mme-Device-Id",
		};

		public IdsDelegateAuth (IdentityOracle oracle) {
			Object (oracle: oracle);
		}

		public async IdsDelegate authenticate (string username, GrandSlamIdentity identity,
				Cancellable? cancellable = null) throws Efni.Error, IOError {
			Gee.Map<string, string> anisette = yield oracle.fetch_anisette (cancellable);
			ValidationData validation = yield oracle.produce_validation_data (cancellable);

			var message = new Soup.Message ("POST", LOGIN_URL);
			apply_headers (message, username, identity, anisette, validation);
			message.set_request_body_from_bytes ("text/x-xml-plist", new Bytes (build_request ().data));

			Bytes response = yield send (message, cancellable);
			return parse_delegate (response, username, identity.adsid);
		}

		private static void apply_headers (Soup.Message message, string username, GrandSlamIdentity identity,
				Gee.Map<string, string> anisette, ValidationData validation) {
			var headers = message.request_headers;
			headers.replace ("Accept", "*/*");
			headers.replace ("User-Agent", USER_AGENT);
			headers.replace ("X-Apple-ADSID", identity.adsid);
			headers.replace ("X-Mme-Nas-Qualify", Base64.encode (validation.data.get_data ()));
			headers.replace ("X-Apple-I-Client-Time", current_timestamp ());
			headers.replace ("X-Apple-Locale", "en_US");
			headers.replace ("X-Apple-I-TimeZone", "UTC");
			foreach (unowned string name in ANISETTE_HEADERS)
				headers.replace (name, anisette[name]);
			headers.replace ("Authorization", "Basic " + Base64.encode (@"$username:$(identity.pet)".data));
		}

		private static string build_request () {
			var ids_delegate = new PlistDict ();
			ids_delegate.set_string ("protocol-version", "4");

			var delegates = new PlistDict ();
			delegates.set_dict ("com.apple.private.ids", ids_delegate);
			delegates.set_dict ("com.apple.mobileme", new PlistDict ());

			var user_info = new PlistDict ();
			user_info.set_string ("client-id", Uuid.string_random ().up ());
			user_info.set_string ("language", "en-US");
			user_info.set_string ("timezone", "America/New_York");

			var request = new Plist ();
			request.set_dict ("delegates", delegates);
			request.set_string ("protocolVersion", "1.0");
			request.set_dict ("userInfo", user_info);
			return request.to_xml ();
		}

		private static IdsDelegate parse_delegate (Bytes response, string username, string adsid) throws Efni.Error {
			try {
				var plist = new Plist.from_data (response.get_data ());
				PlistDict ids = plist.get_dict ("delegates").get_dict ("com.apple.private.ids");
				int64 status = ids.get_integer ("status");
				if (status != 0) {
					throw new Efni.Error.PROTOCOL ("IDS delegate login failed with status %" +
						int64.FORMAT_MODIFIER + "d", status);
				}
				PlistDict service_data = ids.get_dict ("service-data");
				return new IdsDelegate (username, adsid, service_data.get_string ("profile-id"),
					service_data.get_string ("auth-token"));
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed IDS delegate response: %s", e.message);
			}
		}

		private async Bytes send (Soup.Message message, Cancellable? cancellable) throws Efni.Error, IOError {
			try {
				Bytes response = yield session.send_and_read_async (message, Priority.DEFAULT, cancellable);
				if (message.status_code != 200)
					throw new Efni.Error.PROTOCOL ("IDS delegate login returned HTTP %u", message.status_code);
				return response;
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to reach the IDS delegate login endpoint: %s", e.message);
			}
		}

		private static string current_timestamp () {
			return new DateTime.now_utc ().format ("%Y-%m-%dT%H:%M:%SZ");
		}
	}

	public sealed class IdsDelegate : Object {
		public string username {
			get;
			construct;
		}

		public string adsid {
			get;
			construct;
		}

		public string profile_id {
			get;
			construct;
		}

		public string auth_token {
			get;
			construct;
		}

		public IdsDelegate (string username, string adsid, string profile_id, string auth_token) {
			Object (username: username, adsid: adsid, profile_id: profile_id, auth_token: auth_token);
		}
	}
}
