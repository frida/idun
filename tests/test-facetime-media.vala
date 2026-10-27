using Efni;

namespace Idun.FaceTimeMediaTest {
	public void add_tests () {
		GLib.Test.add_func ("/FaceTimeMedia/unwraps-known-answer", unwraps_known_answer);
		GLib.Test.add_func ("/FaceTimeMedia/wraps-and-unwraps-roundtrip", wraps_and_unwraps_roundtrip);
		GLib.Test.add_func ("/FaceTimeMedia/derives-stream-key", derives_stream_key);
		GLib.Test.add_func ("/FaceTimeMedia/derives-control-key", derives_control_key);
		GLib.Test.add_func ("/FaceTimeMedia/builds-participant-data", builds_participant_data);
	}

	private void builds_participant_data () {
		try {
			var data = new FaceTimeParticipantData ();
			data.session_uuid = "2CC7DA48-8AA7-41EA-9662-3F0027EFEC63";
			data.audio_ssrc = 0x12345678;
			data.ntp_time = 17188950392802533376U;
			data.device_type = "Mac17,2";
			data.framework_version = "2235.63.5.2";
			data.os_version = "26A428";
			data.call_id = 457613262;

			var offer = new Plist.from_data (data.build ());
			assert_true (offer.get_string ("vcSessionParticipantKeyUUID") == data.session_uuid);

			assert_true (stream_group_ssrc (offer.get_bytes ("b2n").get_data ()) == data.audio_ssrc);

			uint8[] media_blob = inflate (offer.get_bytes ("vcSessionParticipantKeyMediaBlob"));
			assert_true (audio_settings_ssrc (media_blob) == data.audio_ssrc);
		} catch (GLib.Error e) {
			assert_not_reached ();
		}
	}

	private uint32 stream_group_ssrc (uint8[] negotiation) throws Efni.Error {
		uint8[] group = field_bytes (negotiation, 7);
		uint8[] stream = field_bytes (group, 3);
		return (uint32) field_varint (stream, 4);
	}

	private uint32 audio_settings_ssrc (uint8[] media_blob) throws Efni.Error {
		uint8[] settings = field_bytes (media_blob, 3);
		return (uint32) field_varint (settings, 1);
	}

	private uint8[] field_bytes (uint8[] message, int wanted) throws Efni.Error {
		var reader = new ProtobufReader (message);
		while (reader.has_more) {
			uint8 wire_type;
			int field = reader.read_field (out wire_type);
			if (field == wanted && wire_type == 2)
				return reader.read_bytes ();
			reader.skip (wire_type);
		}
		assert_not_reached ();
	}

	private uint64 field_varint (uint8[] message, int wanted) throws Efni.Error {
		var reader = new ProtobufReader (message);
		while (reader.has_more) {
			uint8 wire_type;
			int field = reader.read_field (out wire_type);
			if (field == wanted && wire_type == 0)
				return reader.read_varint ();
			reader.skip (wire_type);
		}
		assert_not_reached ();
	}

	private uint8[] inflate (Bytes compressed) throws GLib.Error {
		var source = new ConverterInputStream (new MemoryInputStream.from_bytes (compressed),
			new ZlibDecompressor (ZlibCompressorFormat.ZLIB));
		var sink = new MemoryOutputStream.resizable ();
		sink.splice (source, OutputStreamSpliceFlags.CLOSE_SOURCE | OutputStreamSpliceFlags.CLOSE_TARGET);
		return sink.steal_as_bytes ().get_data ();
	}

	private void derives_stream_key () {
		try {
			uint8[] key = FaceTimeMediaCrypto.media_stream_key (decode_hex (MKM), decode_hex (MKS),
				0x12345678);
			assert_true (new Bytes (key).compare (new Bytes (decode_hex (STREAM_KEY))) == 0);
		} catch (Efni.Error e) {
			assert_not_reached ();
		}
	}

	private void derives_control_key () {
		try {
			uint8[] key = FaceTimeMediaCrypto.control_channel_key (decode_hex (MKM), decode_hex (MKS),
				decode_hex (OUR_UUID), decode_hex (PEER_UUID));
			assert_true (new Bytes (key).compare (new Bytes (decode_hex (CONTROL_KEY))) == 0);
		} catch (Efni.Error e) {
			assert_not_reached ();
		}
	}

	private const string MKM = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
	private const string MKS = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
	private const string STREAM_KEY = "3b6b555f7cefa721dff4a270178f590e52858c2cf89cace2413976793047";
	private const string OUR_UUID = "8d633dfb392c44c89fd0c714cd298c2d";
	private const string PEER_UUID = "2cc7da488aa741ea96623f0027efec63";
	private const string CONTROL_KEY = "7d204e272e40610471ff9c00ae8688e84d82cd35c201019f27f42618c179b8b2";

	private void unwraps_known_answer () {
		try {
			uint8[] material = FaceTimeMediaCrypto.unwrap_key_material (new Bytes (KEY_PEM.data),
				decode_hex (SEALED));
			assert_true (new Bytes (material).compare (new Bytes (decode_hex (MATERIAL))) == 0);
		} catch (Efni.Error e) {
			assert_not_reached ();
		}
	}

	private void wraps_and_unwraps_roundtrip () {
		try {
			var key = TetraCrypto.generate_key_agreement_key ();
			uint8[] point = TetraCrypto.public_key_point (key);
			uint8[] material = decode_hex (MATERIAL);

			uint8[] sealed = FaceTimeMediaCrypto.wrap_key_material (point, material);
			assert_true (sealed.length == 65 + material.length + 8);

			uint8[] opened = FaceTimeMediaCrypto.unwrap_key_material (key, sealed);
			assert_true (new Bytes (opened).compare (new Bytes (material)) == 0);
		} catch (Efni.Error e) {
			assert_not_reached ();
		}
	}

	private const string MATERIAL = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
	private const string SEALED = "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794961e4ce4e740931e1b4a401e856c03fb68f91717bbecca2d9113ba22908d952ccf0891d63e4a7ae7";
	private const string KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgO14s9f3IhSF1XObu\n0Y9dR7YJeyveNYoK5o+MRsNzUmyhRANCAAQGqhFB+IgxMaOpVyoLWL0RIc7QFGST\nUcOSEK/G9si1xRKQ20atNEaElSLSRTAs2j9shDHEHXIiIYENleX7v0Ku\n-----END PRIVATE KEY-----\n";

	private uint8[] decode_hex (string hex) {
		var bytes = new uint8[hex.length / 2];
		for (int i = 0; i != bytes.length; i++)
			bytes[i] = (uint8) (hex.substring (i * 2, 2).to_long (null, 16));
		return bytes;
	}
}
