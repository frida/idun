using Efni;

namespace Idun {
	/**
	 * A call's media endpoint: the GStreamer RTP audio pipeline carried over the ICE
	 * transport. Outgoing RTP goes out over the connected ICE path and incoming RTP is
	 * fed back into the pipeline to be decoded, so once the path is up audio flows both
	 * ways. The signaling layer exchanges the descriptions and feeds the peer's in.
	 */
	public sealed class MediaConnection : Object {
		private IceAgent ice;
		private RtpMediaSession media;

		public signal void gathered ();
		public signal void connected ();
		public signal void audio_received (uint8[] samples);

		public MediaConnection (bool controlling, Bytes send_key, Bytes receive_key) {
			ice = new IceAgent (controlling);
			media = new RtpMediaSession (send_key, receive_key);

			media.rtp_ready.connect ((packet) => ice.send (packet));
			ice.received.connect ((packet) => media.deliver_rtp (packet));
			media.audio_ready.connect ((samples) => audio_received (samples));

			ice.gathered.connect (() => gathered ());
			ice.connected.connect (on_connected);
		}

		public void gather () {
			ice.gather ();
		}

		public string local_description () {
			return ice.local_description ();
		}

		public void set_remote_description (string description) {
			ice.set_remote_description (description);
		}

		public void send_audio (uint8[] samples) {
			media.send_audio (samples);
		}

		public void close () {
			media.stop ();
		}

		private bool started;

		private void on_connected () {
			if (started)
				return;
			started = true;
			media.start ();
			connected ();
		}
	}
}
