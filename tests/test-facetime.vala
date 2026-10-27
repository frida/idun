using Efni;

namespace Idun.FaceTimeTest {
	public void add_tests () {
		GLib.Test.add_func ("/FaceTime/media-announcement-round-trips", media_announcement_round_trips);
		GLib.Test.add_func ("/FaceTime/join-status-round-trips", join_status_round_trips);
		GLib.Test.add_func ("/FaceTime/resolves-participant-id", resolves_participant_id);
	}

	private void resolves_participant_id () {
		string[] members = {
			"token:3627DF7A8853A59A5598257818F8A4C0535B00476A22FD95A2F28D22E1E4E9EE/mailto:oravnas@gmail.com",
			"token:D3264B83C3E1238D0BA1F18B3D36EC2F1DCE66735A489C4A1C5AE14CA999E905/mailto:oravnas@gmail.com",
			"token:48609C9A5E99FDAC33A62F9FA665B6DC59702DFF3DE6CB5237B25F4C3C02980A/tel:+4748270645",
			"token:F946664DFD8C7EA0ED58D9062321142231D266F86B458E89AE8E30D69BFAF16E/mailto:oravnas@gmail.com"
		};
		int64[] oravnas_ids = { 7981590510947947922, 1022952488408394525, 2813757547416776297 };
		try {
			int64 id = FaceTimeEndpoint.resolve_participant_id (members, "mailto:oravnas@gmail.com",
				"D3264B83C3E1238D0BA1F18B3D36EC2F1DCE66735A489C4A1C5AE14CA999E905", oravnas_ids);
			assert_true (id == 1022952488408394525);
		} catch (Efni.Error e) {
			assert_not_reached ();
		}
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

	private void join_status_round_trips () {
		try {
			string group = "9C564DE5-EC67-4E38-B8FF-34EA8666FE27";
			string[] members = {
				"token:3627DF7A/mailto:oravnas@gmail.com",
				"token:D3264B83/mailto:oravnas@gmail.com"
			};
			uint8[] context = { 0x10, 0x06 };
			uint8[] media_point = new uint8[65];
			uint8[] participant_data = { 0x01, 0x02, 0x03 };
			uint8[] status = FaceTimeEndpoint.build_join_status (group, members, 1022952488408394525,
				context, media_point, participant_data);

			var parsed = new Plist.from_binary (status);
			assert_true (!parsed.get_boolean ("is-initiator-key"));
			assert_true (parsed.get_boolean ("is-u-plus-one-key"));
			assert_true (parsed.get_string ("fanout-groupID-key") == group);
			assert_true (parsed.get_integer ("join-notification-key") == 2);
			assert_true (parsed.get_bytes ("participant-data-key").compare (new Bytes (participant_data)) == 0);
			assert_true (parsed.get_integer ("participant-id-key") == 1022952488408394525);
			var parsed_members = parsed.get_array ("fanout-groupMembers-key");
			assert_true (parsed_members.length == 2);
			assert_true (parsed_members.get_string (0) == members[0]);
		} catch (GLib.Error e) {
			assert_not_reached ();
		}
	}
}
