using Efni;

namespace Idun {
	/**
	 * Base for the on-disk identity stores: each holds a long-lived credential as an
	 * owner-only property list under the user's config directory, so provisioning
	 * survives across runs and Idun stays a single stable device in the account.
	 */
	public abstract class IdentityStore : Object {
		protected Plist? read () {
			try {
				return new Plist.from_data (location ().load_bytes ().get_data ());
			} catch (GLib.Error e) {
				return null;
			}
		}

		protected void write (Plist plist) throws Efni.Error {
			File file = location ();
			try {
				file.get_parent ().make_directory_with_parents ();
			} catch (GLib.Error e) {
			}
			try {
				file.replace_contents (plist.to_binary (), null, false, PRIVATE | REPLACE_DESTINATION, null);
			} catch (GLib.Error e) {
				throw new Efni.Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		protected File location () {
			return File.new_build_filename (Environment.get_user_config_dir (), "idun", filename ());
		}

		protected abstract string filename ();
	}
}
