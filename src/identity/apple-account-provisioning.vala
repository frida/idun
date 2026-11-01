using Efni;

namespace Idun {
	/**
	 * Fetches the account's provisioned settings from iCloud's setup service. Where the IDS
	 * delegate login hands back a lightly scoped mobileme token, this request authenticates as
	 * the full iCloud account — Basic authorization plus the Grand Slam token — and returns the
	 * per-dataclass provisioning, including the iCloud-scoped mobileme auth token that the
	 * escrow proxy accepts. Idun needs that token to recover the account's escrow records.
	 */
	public sealed class AppleAccountProvisioning : Object {
		public IdentityOracle oracle {
			get;
			construct;
		}

		private Soup.Session session = new Soup.Session ();

		private const string ACCOUNT_SETTINGS_URL = "https://setup.icloud.com/setup/get_account_settings";
		private const string LOGIN_OR_CREATE_URL = "https://setup.icloud.com/setup/login_or_create_account";
		private const string USER_AGENT = "com.apple.iCloudHelper/282 CFNetwork/1498.700.2 Darwin/23.6.0";

		private const string[] ANISETTE_HEADERS = {
			"X-MMe-Client-Info",
			"X-Apple-I-MD",
			"X-Apple-I-MD-M",
			"X-Apple-I-MD-RINFO",
			"X-Apple-I-MD-LU",
			"X-Apple-I-SRL-NO",
			"X-Mme-Device-Id",
		};

		public AppleAccountProvisioning (IdentityOracle oracle) {
			Object (oracle: oracle);
		}

		/**
		 * Registers this device with the iCloud account and returns the provisioning response.
		 * Unlike the delegate login, this posts to the login-or-create endpoint carrying the
		 * device's hardware identifier, which enrolls the device in the account so that the
		 * tokens it hands back are trusted by the escrow proxy. The device identifier defaults
		 * to a random value; set it to the identity this device presents consistently.
		 */
		public async Plist register (string username, GrandSlamIdentity identity, string device_udid,
				Cancellable? cancellable = null) throws Efni.Error, IOError {
			Gee.Map<string, string> anisette = yield oracle.fetch_anisette (cancellable);
			ValidationData validation = yield oracle.produce_validation_data (cancellable);

			var message = new Soup.Message ("POST", LOGIN_OR_CREATE_URL);
			apply_headers (message, username, identity, anisette, validation);
			message.request_headers.replace ("Device-UDID", device_udid);
			message.set_request_body_from_bytes ("application/xml", new Bytes (build_register_request ().data));

			try {
				Bytes response = yield session.send_and_read_async (message, Priority.DEFAULT, cancellable);
				string? dump = Environment.get_variable ("IDUN_PROVISION_DUMP");
				if (dump != null)
					FileUtils.set_data (dump, response.get_data ());
				if (message.status_code != 200)
					throw new Efni.Error.PROTOCOL ("loginOrCreateAccount returned HTTP %u", message.status_code);
				return new Plist.from_data (response.get_data ());
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed loginOrCreateAccount response: %s", e.message);
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to reach the iCloud setup service: %s", e.message);
			}
		}

		public async Plist fetch_account_settings (string username, GrandSlamIdentity identity,
				Cancellable? cancellable = null) throws Efni.Error, IOError {
			Gee.Map<string, string> anisette = yield oracle.fetch_anisette (cancellable);
			ValidationData validation = yield oracle.produce_validation_data (cancellable);

			var message = new Soup.Message ("POST", ACCOUNT_SETTINGS_URL);
			apply_headers (message, username, identity, anisette, validation);
			message.set_request_body_from_bytes ("application/xml", new Bytes (build_request ().data));

			try {
				Bytes response = yield session.send_and_read_async (message, Priority.DEFAULT, cancellable);
				string? dump = Environment.get_variable ("IDUN_PROVISION_DUMP");
				if (dump != null)
					FileUtils.set_data (dump, response.get_data ());
				if (message.status_code != 200)
					throw new Efni.Error.PROTOCOL ("get_account_settings returned HTTP %u", message.status_code);
				return new Plist.from_data (response.get_data ());
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed get_account_settings response: %s", e.message);
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to reach the iCloud setup service: %s", e.message);
			}
		}

		private static void apply_headers (Soup.Message message, string username, GrandSlamIdentity identity,
				Gee.Map<string, string> anisette, ValidationData validation) {
			var headers = message.request_headers;
			headers.replace ("Accept", "*/*");
			headers.replace ("User-Agent", USER_AGENT);
			headers.replace ("X-Apple-ADSID", identity.adsid);
			headers.replace ("X-Apple-GS-Token", Base64.encode (@"$(identity.dsid):$(identity.icloud_auth_token)".data));
			headers.replace ("X-Mme-Nas-Qualify", Base64.encode (validation.data.get_data ()));
			headers.replace ("X-Apple-I-Client-Time", current_timestamp ());
			headers.replace ("X-Apple-Locale", "en_US");
			headers.replace ("X-Apple-I-TimeZone", "UTC");
			foreach (unowned string name in ANISETTE_HEADERS)
				headers.replace (name, anisette[name]);
			headers.replace ("Authorization", "Basic " + Base64.encode (@"$username:$(identity.pet)".data));
		}

		private static string build_request () {
			var request = new Plist ();
			return request.to_xml ();
		}

		private static string build_register_request () {
			var user_info = new PlistDict ();
			user_info.set_string ("timezone", "America/New_York");
			user_info.set_string ("language", "en-US");

			var request = new Plist ();
			request.set_string ("protocolVersion", "1.0");
			request.set_dict ("userInfo", user_info);
			return request.to_xml ();
		}

		private static string current_timestamp () {
			return new DateTime.now_utc ().format ("%Y-%m-%dT%H:%M:%SZ");
		}
	}
}
