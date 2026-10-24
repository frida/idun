using Efni;

namespace Idun {
	/**
	 * The audio half of a call's media, as GStreamer RTP secured with SRTP: outgoing
	 * audio is encoded to Opus, packetised into RTP and encrypted under our master key
	 * before being handed out to send, while SRTP that arrives from the peer is
	 * decrypted under its key, depacketised and decoded back to audio. The two
	 * directions are independent pipelines so each flows as soon as its path is up.
	 */
	public sealed class RtpMediaSession : Object {
		private Bytes send_key;
		private Bytes receive_key;

		private Gst.Pipeline send_pipeline;
		private Gst.App.Src audio_in;
		private Gst.App.Sink rtp_out;

		private Gst.Pipeline receive_pipeline;
		private Gst.App.Src rtp_in;
		private Gst.App.Sink audio_out;

		private const int CLOCK_RATE = 48000;
		private const int PAYLOAD_TYPE = 111;
		private const string CIPHER = "aes-128-icm";
		private const string AUTH = "hmac-sha1-80";

		public const int MASTER_KEY_LENGTH = 30;

		public signal void rtp_ready (uint8[] packet);
		public signal void audio_ready (uint8[] samples);

		public RtpMediaSession (Bytes send_key, Bytes receive_key) {
			this.send_key = send_key;
			this.receive_key = receive_key;
			build_send_pipeline ();
			build_receive_pipeline ();
		}

		public void start () {
			send_pipeline.set_state (PLAYING);
			receive_pipeline.set_state (PLAYING);
		}

		public void stop () {
			send_pipeline.set_state (NULL);
			receive_pipeline.set_state (NULL);
		}

		public void send_audio (uint8[] samples) {
			audio_in.push_buffer (new Gst.Buffer.wrapped (samples));
		}

		public void deliver_rtp (uint8[] packet) {
			rtp_in.push_buffer (new Gst.Buffer.wrapped (packet));
		}

		private void build_send_pipeline () {
			audio_in = (Gst.App.Src) Gst.ElementFactory.make ("appsrc", "audio_in");
			var convert = Gst.ElementFactory.make ("audioconvert", null);
			var encoder = Gst.ElementFactory.make ("opusenc", null);
			var payloader = Gst.ElementFactory.make ("rtpopuspay", null);
			var protector = Gst.ElementFactory.make ("srtpenc", null);
			rtp_out = (Gst.App.Sink) Gst.ElementFactory.make ("appsink", "rtp_out");

			audio_in.set ("is-live", true, "format", Gst.Format.TIME, "do-timestamp", true);
			audio_in.caps = new Gst.Caps.simple ("audio/x-raw",
				"format", typeof (string), "S16LE",
				"rate", typeof (int), CLOCK_RATE,
				"channels", typeof (int), 1,
				"layout", typeof (string), "interleaved");
			payloader.set ("pt", PAYLOAD_TYPE);
			protector.set ("key", new Gst.Buffer.wrapped (send_key.get_data ()));
			rtp_out.set ("emit-signals", true, "sync", false, "async", false);
			rtp_out.new_sample.connect (on_rtp_out);

			send_pipeline = new Gst.Pipeline ("send");
			send_pipeline.add_many (audio_in, convert, encoder, payloader, protector, rtp_out);
			audio_in.link_many (convert, encoder, payloader, protector, rtp_out);
		}

		private void build_receive_pipeline () {
			rtp_in = (Gst.App.Src) Gst.ElementFactory.make ("appsrc", "rtp_in");
			var unprotector = Gst.ElementFactory.make ("srtpdec", null);
			var depayloader = Gst.ElementFactory.make ("rtpopusdepay", null);
			var decoder = Gst.ElementFactory.make ("opusdec", null);
			audio_out = (Gst.App.Sink) Gst.ElementFactory.make ("appsink", "audio_out");

			rtp_in.set ("is-live", true, "format", Gst.Format.TIME, "do-timestamp", true);
			rtp_in.caps = new Gst.Caps.simple ("application/x-srtp",
				"media", typeof (string), "audio",
				"clock-rate", typeof (int), CLOCK_RATE,
				"encoding-name", typeof (string), "OPUS",
				"payload", typeof (int), PAYLOAD_TYPE,
				"srtp-cipher", typeof (string), CIPHER,
				"srtp-auth", typeof (string), AUTH,
				"srtcp-cipher", typeof (string), CIPHER,
				"srtcp-auth", typeof (string), AUTH);
			audio_out.set ("emit-signals", true, "sync", false, "async", false);
			audio_out.new_sample.connect (on_audio_out);
			GLib.Signal.connect (unprotector, "request-key", (GLib.Callback) on_request_key, this);

			receive_pipeline = new Gst.Pipeline ("receive");
			receive_pipeline.add_many (rtp_in, unprotector, depayloader, decoder, audio_out);
			rtp_in.link (unprotector);
			unprotector.link_many (depayloader, decoder, audio_out);
		}

		private static Gst.Caps on_request_key (Gst.Element unprotector, uint ssrc, RtpMediaSession self) {
			return new Gst.Caps.simple ("application/x-srtp",
				"srtp-key", typeof (Gst.Buffer), new Gst.Buffer.wrapped (self.receive_key.get_data ()),
				"srtp-cipher", typeof (string), CIPHER,
				"srtp-auth", typeof (string), AUTH,
				"srtcp-cipher", typeof (string), CIPHER,
				"srtcp-auth", typeof (string), AUTH);
		}

		private Gst.FlowReturn on_rtp_out () {
			uint8[]? packet = pull (rtp_out);
			if (packet != null)
				rtp_ready (packet);
			return OK;
		}

		private Gst.FlowReturn on_audio_out () {
			uint8[]? samples = pull (audio_out);
			if (samples != null)
				audio_ready (samples);
			return OK;
		}

		private static uint8[]? pull (Gst.App.Sink sink) {
			Gst.Sample? sample = sink.pull_sample ();
			if (sample == null)
				return null;
			Gst.MapInfo info;
			if (!sample.get_buffer ().map (out info, READ))
				return null;
			uint8[] copy = info.data;
			sample.get_buffer ().unmap (info);
			return copy;
		}
	}
}
