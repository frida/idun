using Efni;

namespace Idun.NetworkStackTest {
	public void add_tests () {
		GLib.Test.add_func ("/NetworkStack/tun-stack-emits-outgoing-datagrams", () => {
			var h = new Harness ((h) => tun_stack_emits_outgoing_datagrams.begin (h as Harness));
			h.run ();
		});
	}

	private async void tun_stack_emits_outgoing_datagrams (Harness h) {
		TunNetworkStack netstack;
		try {
			netstack = new TunNetworkStack (null, new InetAddress.from_string ("fd1d:0d1d::1"), 1500);
		} catch (Efni.Error e) {
			GLib.Test.skip (e.message);
			h.done ();
			return;
		}

		Bytes? syn = null;
		netstack.outgoing_datagrams.connect (datagrams => {
			foreach (var datagram in datagrams) {
				if (syn == null && is_tcp_segment (datagram)) {
					syn = datagram;
					tun_stack_emits_outgoing_datagrams.callback ();
				}
			}
		});

		var cancellable = new Cancellable ();
		netstack.open_tcp_connection.begin (new InetSocketAddress.from_string ("fd1d:0d1d::2", 1234), cancellable);
		yield;
		cancellable.cancel ();

		netstack.stop ();

		h.done ();
	}

	private bool is_tcp_segment (Bytes datagram) {
		var reader = new BufferReader (new Buffer (datagram, BIG_ENDIAN));
		try {
			uint32 version_and_class = reader.read_uint32 ();
			reader.skip (2);
			uint8 next_header = reader.read_uint8 ();
			return (version_and_class >> 28) == 6 && next_header == 6;
		} catch (Efni.Error e) {
			return false;
		}
	}

	private class Harness : Test.AsyncHarness {
		public Harness (owned Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
		}
	}
}
