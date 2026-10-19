namespace Idun.PlistTest {
	public void add_tests () {
		GLib.Test.add_func ("/Plist/can-construct-from-xml-document", can_construct_from_xml_document);
		GLib.Test.add_func ("/Plist/to-xml-yields-complete-document", to_xml_yields_complete_document);
#if DARWIN
		GLib.Test.add_func ("/Plist/output-matches-apple-implementation", output_matches_apple_implementation);
#endif
	}

	private void can_construct_from_xml_document () {
		var xml = """
			<?xml version="1.0" encoding="UTF-8"?>
			<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
			<plist version="1.0">
			<dict>
				<key>DeviceID</key>
				<integer>2</integer>
				<key>MessageType</key>
				<string>Attached</string>
				<key>Properties</key>
				<dict>
					<key>ConnectionType</key>
					<string>USB</string>
					<key>DeviceID</key>
					<integer>2</integer>
					<key>LocationID</key>
					<integer>0</integer>
					<key>ProductID</key>
					<integer>4759</integer>
					<key>SerialNumber</key>
					<string>220f889780dda462091a65df48b9b6aedb05490f</string>
					<key>ExtraBoolTrue</key>
					<true/>
					<key>ExtraBoolFalse</key>
					<false/>
					<key>ExtraData</key>
					<data>AQID</data>
					<key>ExtraStrings</key>
					<array>
						<string>A</string>
						<string>B</string>
					</array>
				</dict>
			</dict>
			</plist>
		""";

		try {
			var plist = new Plist.from_xml (xml);
			assert_true (plist.size == 3);
			assert_true (plist.get_integer ("DeviceID") == 2);
			assert_true (plist.get_string ("MessageType") == "Attached");

			var properties = plist.get_dict ("Properties");
			assert_true (properties.size == 9);
			assert_true (properties.get_string ("ConnectionType") == "USB");
			assert_true (properties.get_integer ("DeviceID") == 2);
			assert_true (properties.get_integer ("LocationID") == 0);
			assert_true (properties.get_integer ("ProductID") == 4759);
			assert_true (properties.get_string ("SerialNumber") == "220f889780dda462091a65df48b9b6aedb05490f");

			assert_true (properties.get_boolean ("ExtraBoolTrue") == true);
			assert_true (properties.get_boolean ("ExtraBoolFalse") == false);

			var extra_data = properties.get_bytes ("ExtraData");
			assert_true (extra_data.length == 3);
			assert_true (extra_data[0] == 0x01);
			assert_true (extra_data[1] == 0x02);
			assert_true (extra_data[2] == 0x03);

			var extra_strings = properties.get_array ("ExtraStrings");
			assert_true (extra_strings.length == 2);
			assert_true (extra_strings.get_string (0) == "A");
			assert_true (extra_strings.get_string (1) == "B");
		} catch (PlistError e) {
			printerr ("%s\n", e.message);
			assert_not_reached ();
		}
	}

	private void to_xml_yields_complete_document () {
		var plist = new Plist ();
		plist.set_string ("MessageType", "Detached");
		plist.set_integer ("DeviceID", 2);

		var properties = new PlistDict ();
		properties.set_string ("ConnectionType", "USB");
		properties.set_integer ("DeviceID", 2);
		properties.set_boolean ("ExtraBoolTrue", true);
		properties.set_boolean ("ExtraBoolFalse", false);
		properties.set_bytes ("ExtraData", new Bytes ({ 0x01, 0x02, 0x03 }));
		var extra_strings = new PlistArray ();
		extra_strings.add_string ("A");
		extra_strings.add_string ("B");
		properties.set_array ("ExtraStrings", extra_strings);
		plist.set_dict ("Properties", properties);

		var actual_xml = plist.to_xml ();
		var expected_xml =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
			"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
			"<plist version=\"1.0\">\n" +
			"<dict>\n" +
			"	<key>DeviceID</key>\n" +
			"	<integer>2</integer>\n" +
			"	<key>MessageType</key>\n" +
			"	<string>Detached</string>\n" +
			"	<key>Properties</key>\n" +
			"	<dict>\n" +
			"		<key>ConnectionType</key>\n" +
			"		<string>USB</string>\n" +
			"		<key>DeviceID</key>\n" +
			"		<integer>2</integer>\n" +
			"		<key>ExtraBoolFalse</key>\n" +
			"		<false/>\n" +
			"		<key>ExtraBoolTrue</key>\n" +
			"		<true/>\n" +
			"		<key>ExtraData</key>\n" +
			"		<data>AQID</data>\n" +
			"		<key>ExtraStrings</key>\n" +
			"		<array>\n" +
			"			<string>A</string>\n" +
			"			<string>B</string>\n" +
			"		</array>\n" +
			"	</dict>\n" +
			"</dict>\n" +
			"</plist>\n";
		assert_true (actual_xml == expected_xml);
	}

#if DARWIN
	private void output_matches_apple_implementation () {
		var request = new Plist ();
		request.set_string ("Command", "Lookup");

		var options = new PlistDict ();
		request.set_dict ("ClientOptions", options);

		var attributes = new PlistArray ();
		options.set_array ("ReturnAttributes", attributes);
		attributes.add_string ("ApplicationType");
		attributes.add_string ("IsAppClip");
		attributes.add_string ("SBAppTags");
		attributes.add_string ("CFBundleIdentifier");
		attributes.add_string ("CFBundleDisplayName");
		attributes.add_string ("CFBundleShortVersionString");
		attributes.add_string ("CFBundleVersion");
		attributes.add_string ("Path");
		attributes.add_string ("Container");
		attributes.add_string ("GroupContainers");
		attributes.add_string ("Entitlements");

		var ids = new PlistArray ();
		options.set_array ("BundleIDs", ids);
		ids.add_string ("UUU");

		string? error_message;

		string our_xml = request.to_xml ();
		uint8[] our_bplist = request.to_binary ();

		uint8[]? apple_bplist = to_binary_using_apple_implementation (our_xml.data, out error_message);
		if (error_message != null)
			printerr ("Oops: %s\n", error_message);
		assert_nonnull (apple_bplist);
		assert_null (error_message);

		/*
		try {
			var home_dir = Environment.get_home_dir ();
			FileUtils.set_data (Path.build_filename (home_dir, "frida-test-apple.plist"), apple_bplist);
			FileUtils.set_data (Path.build_filename (home_dir, "frida-test-our.plist"), our_bplist);
		} catch (FileError e) {
			assert_not_reached ();
		}
		*/

		string? apple_xml = to_xml_using_apple_implementation (our_bplist, out error_message);
		if (error_message != null)
			printerr ("Oops: %s\n", error_message);
		assert_nonnull (apple_xml);
		assert_null (error_message);

		assert_cmpstr (our_xml, EQ, apple_xml);
		assert_cmpstr (Base64.encode (our_bplist), EQ, Base64.encode (apple_bplist));
	}

	private extern uint8[]? to_binary_using_apple_implementation (uint8[] data, out string? error_message);
	private extern string? to_xml_using_apple_implementation (uint8[] data, out string? error_message);
#endif
}
