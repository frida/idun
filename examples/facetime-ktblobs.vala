namespace Idun.Examples {
	private static int main (string[] args) {
		try {
			var message = MessageIdentity.load_or_generate (new MessageIdentityStore ());
			var ngm = NgmIdentity.load_or_generate (new NgmIdentityStore ());
			double timestamp = (double) get_real_time () / 1000000.0;
			print ("legacy %s\n", hex (message.public_key.get_data ()));
			print ("ngmidentity %s\n", hex (ngm.device_identity_data (15)));
			print ("ngmprekey %s\n", hex (ngm.device_prekey_data (timestamp, 15)));
		} catch (GLib.Error e) {
			printerr ("error: %s\n", e.message);
			return 1;
		}
		return 0;
	}

	private static string hex (uint8[] data) {
		var sb = new StringBuilder ();
		foreach (uint8 b in data)
			sb.append_printf ("%02x", b);
		return sb.str;
	}
}
