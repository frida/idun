using Efni;

namespace Idun {
	/**
	 * The IDS service bag: the directory of endpoint URLs Apple publishes for the
	 * identity services. Fetched once, then consulted by name for the registration
	 * and authentication endpoints.
	 */
	public sealed class IdsBag : Object {
		private Gee.Map<string, string> entries;

		private const string BAG_URL = "https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3";

		private IdsBag (Gee.Map<string, string> entries) {
			this.entries = entries;
		}

		public static async IdsBag fetch (Soup.Session session, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			Bytes response;
			try {
				response = yield session.send_and_read_async (new Soup.Message ("GET", BAG_URL),
					Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to fetch the IDS bag: %s", e.message);
			}

			var entries = new Gee.HashMap<string, string> ();
			try {
				var envelope = new Plist.from_data (response.get_data ());
				var bag = new Plist.from_data (envelope.get_bytes ("bag").get_data ());
				foreach (string key in bag.keys) {
					try {
						entries[key] = bag.get_string (key);
					} catch (PlistError e) {
					}
				}
			} catch (PlistError e) {
				throw new Efni.Error.PROTOCOL ("Malformed IDS bag: %s", e.message);
			}
			return new IdsBag (entries);
		}

		public string lookup (string key) throws Efni.Error {
			string? url = entries[key];
			if (url == null)
				throw new Efni.Error.PROTOCOL ("IDS bag is missing key: %s", key);
			return url;
		}
	}
}
