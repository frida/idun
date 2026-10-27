namespace Idun {
	/**
	 * The media offer a FaceTime participant publishes when it joins a call: the binary
	 * property list that carries the stream negotiation the peers key their SRTP from.
	 * It pairs a protobuf describing the participant's audio streams and codecs with a
	 * zlib-compressed Viceroy blob holding the same offer in the call's legacy form, and
	 * a small blob naming the device. Idun answers audio only, so the offer advertises a
	 * single AAC-ELD audio stream group and no camera.
	 */
	public sealed class FaceTimeParticipantData : Object {
		public string session_uuid { get; set; }
		public uint32 audio_ssrc { get; set; }
		public uint64 ntp_time { get; set; }
		public string device_type { get; set; }
		public string framework_version { get; set; }
		public string os_version { get; set; }
		public uint32 call_id { get; set; }

		private const int AUDIO_CODEC_TYPE = 2;
		private const int AUDIO_PAYLOAD = 100;
		private const int AUDIO_SAMPLE_RATE = 24000;
		private const int AUDIO_CIPHER_SUITE = 4;
		private const int AUDIO_STREAM_GROUP = 17;
		private const int MIC_PAYLOADS = 47;
		private const int MIC_CIPHER_SUITES = 21;
		private const uint32 AUDIO_UNIT_MODEL = 65792;
		private const int AUDIO_SUPPORT_FLAGS = 1;
		private const int AUDIO_PAYLOAD_FLAGS = 20095;
		private const int AUDIO_SECONDARY_FLAGS = 19058;
		private const uint32 VIDEO_FEATURES = 0x0fff003d;
		private const int BLOB_VERSION = 2;
		private const int MEDIA_CONTROL_VERSION = 1;
		private const string USER_AGENT = "Viceroy 1.7.0/GK";

		public uint8[] build () throws Efni.Error {
			var plist = new Plist ();
			plist.set_string ("vcSessionParticipantKeyUUID", session_uuid);
			plist.set_bytes ("b2n", new Bytes (build_negotiation ()));
			plist.set_bytes ("vcSessionParticipantKeyMediaBlob", deflate (new Bytes (build_media_blob ())));
			plist.set_bytes ("vcSessionParticipantKeyCallInfoBlob", new Bytes (build_call_info ()));
			return plist.to_binary ();
		}

		private uint8[] build_negotiation () {
			var general = new ProtobufWriter ()
				.append_varint (1, ntp_time)
				.append_varint (5, 2)
				.append_varint (6, 1);

			var codec_support = new ProtobufWriter ()
				.append_bytes (2, i2osp_le (VIDEO_FEATURES, 4));

			var microphone = new ProtobufWriter ()
				.append_varint (1, audio_ssrc)
				.append_varint (2, MIC_PAYLOADS)
				.append_varint (3, MIC_CIPHER_SUITES);

			var payload = new ProtobufWriter ()
				.append_varint (1, AUDIO_CODEC_TYPE)
				.append_varint (2, AUDIO_PAYLOAD)
				.append_varint (4, 4)
				.append_varint (7, AUDIO_SAMPLE_RATE)
				.append_varint (8, AUDIO_CIPHER_SUITE);

			var stream = new ProtobufWriter ()
				.append_varint (2, 1)
				.append_varint (4, audio_ssrc)
				.append_varint (9, 0);

			var stream_group = new ProtobufWriter ()
				.append_varint (1, AUDIO_STREAM_GROUP)
				.append_bytes (2, payload.data)
				.append_bytes (3, stream.data);

			return new ProtobufWriter ()
				.append_bytes (1, general.data)
				.append_bytes (3, codec_support.data)
				.append_bytes (4, microphone.data)
				.append_bytes (7, stream_group.data)
				.data;
		}

		private uint8[] build_media_blob () {
			var audio_settings = new ProtobufWriter ()
				.append_varint (1, audio_ssrc)
				.append_varint (2, AUDIO_UNIT_MODEL)
				.append_varint (3, AUDIO_SUPPORT_FLAGS)
				.append_varint (4, AUDIO_PAYLOAD_FLAGS)
				.append_varint (5, AUDIO_SECONDARY_FLAGS)
				.append_varint (6, 1);

			return new ProtobufWriter ()
				.append_varint (1, 1)
				.append_varint (2, 1)
				.append_bytes (3, audio_settings.data)
				.append_bytes (6, USER_AGENT.data)
				.append_varint (13, ntp_time)
				.append_varint (14, BLOB_VERSION)
				.append_varint (16, MEDIA_CONTROL_VERSION)
				.data;
		}

		private uint8[] build_call_info () {
			return new ProtobufWriter ()
				.append_varint (1, call_id)
				.append_varint (2, 1)
				.append_bytes (3, device_type.data)
				.append_bytes (4, framework_version.data)
				.append_bytes (5, os_version.data)
				.data;
		}

		private static uint8[] i2osp_le (uint64 value, int length) {
			var octets = new uint8[length];
			for (int i = 0; i != length; i++) {
				octets[i] = (uint8) value;
				value >>= 8;
			}
			return octets;
		}

		private static Bytes deflate (Bytes data) throws Efni.Error {
			try {
				var source = new ConverterInputStream (new MemoryInputStream.from_bytes (data),
					new ZlibCompressor (ZlibCompressorFormat.ZLIB));
				var sink = new MemoryOutputStream.resizable ();
				sink.splice (source, OutputStreamSpliceFlags.CLOSE_SOURCE | OutputStreamSpliceFlags.CLOSE_TARGET);
				return sink.steal_as_bytes ();
			} catch (GLib.Error e) {
				throw new Efni.Error.PROTOCOL ("Unable to compress FaceTime media offer: %s", e.message);
			}
		}
	}
}
