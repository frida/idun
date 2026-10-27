using Efni;

namespace Idun.FaceTimeTest {
	public void add_tests () {
		GLib.Test.add_func ("/FaceTime/media-announcement-round-trips", media_announcement_round_trips);
	}

	private void media_announcement_round_trips () {
		try {
			Bytes media_key = FaceTimeEndpoint.generate_media_key ();
			uint8[] point = FaceTimeEndpoint.media_public_point (media_key);
			assert_true (point.length == 65);
			assert_true (point[0] == 0x04);

			string group = "94D5B789-4A0B-45D5-A4A5-A0CC2F31A15B";
			uint8[] announcement = FaceTimeEndpoint.build_media_announcement (group, point);

			var parsed = new Plist.from_binary (announcement);
			assert_true (new Bytes (parsed.get_bytes ("rtmpk").get_data ()).compare (new Bytes (point)) == 0);
			assert_true (parsed.get_integer ("rtmpwm") == 1);
			assert_true (parsed.get_string ("s") == group);
			assert_true (parsed.get_string ("fanout-groupID-key") == group);
		} catch (GLib.Error e) {
			assert_not_reached ();
		}
	}
}
