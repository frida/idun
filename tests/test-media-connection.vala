using Efni;

namespace Idun.MediaConnectionTest {
	public void add_tests () {
		GLib.Test.add_func ("/MediaConnection/carries-audio-over-ice", carries_audio_over_ice);
	}

	private void carries_audio_over_ice () {
		new Harness ((h) => {
			var host = (Harness) h;

			var alice = new MediaConnection (true);
			var bob = new MediaConnection (false);
			host.keep_alive (alice);
			host.keep_alive (bob);

			alice.gathered.connect (() => bob.set_remote_description (alice.local_description ()));
			bob.gathered.connect (() => alice.set_remote_description (bob.local_description ()));

			alice.connected.connect (() => {
				host.push (() => {
					alice.send_audio (new uint8[1920]);
					return !host.finished;
				});
			});

			bool done = false;
			bob.audio_received.connect ((samples) => {
				if (done || samples.length == 0)
					return;
				done = true;
				host.done ();
			});

			alice.gather ();
			bob.gather ();
		}).run ();
	}

	private class Harness : Test.AsyncHarness {
		private Gee.ArrayList<Object> alive = new Gee.ArrayList<Object> ();
		public bool finished;

		public Harness (owned Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
		}

		public void keep_alive (Object o) {
			alive.add (o);
		}

		public void push (owned SourceFunc f) {
			Timeout.add (20, (owned) f);
		}

		public override void done () {
			finished = true;
			base.done ();
		}
	}
}
