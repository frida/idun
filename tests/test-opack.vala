using Efni;

namespace Idun.OpackTest {
	public void add_tests () {
		GLib.Test.add_func ("/Opack/round-trips-dictionary", round_trips_dictionary);
		GLib.Test.add_func ("/Opack/rejects-truncated-input", rejects_truncated_input);
	}

	private void round_trips_dictionary () {
		var data = new Bytes ({ 0x01, 0x02, 0x03 });

		var opack = new OpackBuilder ()
			.begin_dictionary ()
				.set_member_name ("name")
				.add_string_value ("idun")
				.set_member_name ("payload")
				.add_data_value (data)
			.end_dictionary ()
			.build ();

		try {
			var reader = new VariantReader (OpackParser.parse (opack));

			assert_cmpstr (reader.read_member ("name").get_string_value (), EQ, "idun");
			reader.end_member ();

			assert_true (reader.read_member ("payload").get_data_value ().compare (data) == 0);
			reader.end_member ();
		} catch (Efni.Error e) {
			printerr ("%s\n", e.message);
			assert_not_reached ();
		}
	}

	private void rejects_truncated_input () {
		var opack = new OpackBuilder ()
			.begin_dictionary ()
				.set_member_name ("name")
				.add_string_value ("idun")
			.end_dictionary ()
			.build ();
		var truncated = new Bytes (opack.get_data ()[0:opack.get_size () - 2]);

		try {
			OpackParser.parse (truncated);
			assert_not_reached ();
		} catch (Efni.Error e) {
			assert_true (e is Efni.Error.PROTOCOL);
		}
	}
}
