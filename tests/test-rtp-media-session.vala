using Efni;

namespace Idun.RtpMediaSessionTest {
	public void add_tests () {
		GLib.Test.add_func ("/RtpMediaSession/encodes-and-decodes-audio", encodes_and_decodes_audio);
	}

	private void encodes_and_decodes_audio () {
		new Harness ((h) => {
			var host = (Harness) h;

			var key = new Bytes (test_key ());
			var session = new RtpMediaSession (key, key);
			host.keep_alive (session);

			session.rtp_ready.connect ((packet) => session.deliver_rtp (packet));

			bool done = false;
			session.audio_ready.connect ((samples) => {
				if (done || samples.length == 0)
					return;
				done = true;
				host.done ();
			});

			session.start ();

			Timeout.add (20, () => {
				if (done)
					return Source.REMOVE;
				session.send_audio (new uint8[1920]);
				return Source.CONTINUE;
			});
		}).run ();
	}

	private static uint8[] test_key () {
		var key = new uint8[RtpMediaSession.MASTER_KEY_LENGTH];
		for (int i = 0; i != key.length; i++)
			key[i] = (uint8) (i + 1);
		return key;
	}

	private class Harness : Test.AsyncHarness {
		private Gee.ArrayList<Object> alive = new Gee.ArrayList<Object> ();

		public Harness (owned Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
		}

		public void keep_alive (Object o) {
			alive.add (o);
		}

		protected override uint provide_timeout () {
			return 10;
		}
	}
}
