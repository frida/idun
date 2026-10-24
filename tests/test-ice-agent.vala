using Efni;

namespace Idun.IceAgentTest {
	public void add_tests () {
		GLib.Test.add_func ("/IceAgent/connects-and-carries-a-packet", connects_and_carries_a_packet);
	}

	private void connects_and_carries_a_packet () {
		new Harness ((h) => {
			var host = (Harness) h;

			var alice = new IceAgent (true);
			var bob = new IceAgent (false);
			host.keep_alive (alice);
			host.keep_alive (bob);

			alice.gathered.connect (() => bob.set_remote_description (alice.local_description ()));
			bob.gathered.connect (() => alice.set_remote_description (bob.local_description ()));

			bool sent = false;
			alice.connected.connect (() => {
				if (sent)
					return;
				sent = true;
				alice.send ("ping".data);
			});
			bob.received.connect ((data) => {
				assert_true (new Bytes (data).compare (new Bytes ("ping".data)) == 0);
				host.done ();
			});

			alice.gather ();
			bob.gather ();
		}).run ();
	}

	private class Harness : Test.AsyncHarness {
		private Gee.ArrayList<Object> alive = new Gee.ArrayList<Object> ();

		public Harness (owned Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
		}

		public void keep_alive (Object o) {
			alive.add (o);
		}
	}
}
