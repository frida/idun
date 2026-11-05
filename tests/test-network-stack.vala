using Efni;

namespace Idun.NetworkStackTest {
	public void add_tests () {
		GLib.Test.add_func ("/NetworkStack/tun-stack-emits-outgoing-datagrams", () => {
			var h = new Harness ((h) => tun_stack_emits_outgoing_datagrams.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/NetworkStack/lwip-stack-reports-close-during-connect", () => {
			var h = new Harness ((h) => lwip_stack_reports_close_during_connect.begin (h as Harness));
			h.run ();
		});
	}

	private async void lwip_stack_reports_close_during_connect (Harness h) {
		var netstack = new LwipNetworkStack (null, new InetAddress.from_string ("fd1d:0d1d::1"), 1500);

		bool answered = false;
		netstack.outgoing_datagrams.connect (datagrams => {
			foreach (var datagram in datagrams) {
				if (answered || !is_tcp_segment (datagram) || (tcp_flags_of (datagram) & TCP_SYN) == 0)
					continue;
				answered = true;

				var replies = new Gee.ArrayList<Bytes> ();
				replies.add (make_reply (datagram, TCP_SYN | TCP_ACK, 0));
				replies.add (make_reply (datagram, TCP_FIN | TCP_ACK, 1));
				netstack.handle_incoming_datagrams.begin (replies);
				wait_for_lwip_thread (netstack);
			}
		});

		IOStream stream;
		try {
			stream = yield netstack.open_tcp_connection (new InetSocketAddress.from_string ("fd1d:0d1d::2", 1234), null);
		} catch (GLib.Error e) {
			printerr ("open_tcp_connection() failed: %s\n", e.message);
			GLib.Test.fail ();
			netstack.stop ();
			h.done ();
			return;
		}

		var input = (PollableInputStream) stream.input_stream;
		var output = (PollableOutputStream) stream.output_stream;

		if (input.is_readable ()) {
			try {
				var n = input.read_nonblocking (new uint8[1]);
				if (n != 0) {
					printerr ("Expected EOF, got %zd bytes\n", n);
					GLib.Test.fail ();
				}
			} catch (GLib.Error e) {
				if (e is IOError.WOULD_BLOCK)
					printerr ("Connection claims to be readable but reads would block; async readers would spin\n");
				else
					printerr ("Expected EOF, got error: %s\n", e.message);
				GLib.Test.fail ();
			}
		} else {
			printerr ("Peer closed the connection but it never became readable; readers would wait forever\n");
			GLib.Test.fail ();
		}

		bool claims_writable = output.is_writable ();
		try {
			output.write_nonblocking (new uint8[] { 0x2a });
			printerr ("Write to closed connection succeeded\n");
			GLib.Test.fail ();
		} catch (GLib.Error e) {
			if (e is IOError.WOULD_BLOCK && claims_writable) {
				printerr ("Connection claims to be writable but writes would block; async writers would spin\n");
				GLib.Test.fail ();
			}
		}

		netstack.stop ();

		h.done ();
	}

	private void wait_for_lwip_thread (LwipNetworkStack netstack) {
		try {
			netstack.create_udp_socket ();
		} catch (Efni.Error e) {
			assert_not_reached ();
		}
	}

	private const uint8 TCP_FIN = 0x01;
	private const uint8 TCP_SYN = 0x02;
	private const uint8 TCP_ACK = 0x10;

	private const size_t IPV6_HEADER_SIZE = 40;
	private const size_t TCP_HEADER_SIZE = 20;
	private const uint32 PEER_ISN = 1000;

	private uint8 tcp_flags_of (Bytes datagram) {
		return datagram.get_data ()[IPV6_HEADER_SIZE + 13];
	}

	private Bytes make_reply (Bytes request, uint8 flags, uint32 seq_offset) {
		unowned uint8[] req = request.get_data ();
		var p = new uint8[IPV6_HEADER_SIZE + TCP_HEADER_SIZE];

		p[0] = 0x60;
		p[4] = (uint8) (TCP_HEADER_SIZE >> 8);
		p[5] = (uint8) TCP_HEADER_SIZE;
		p[6] = 6;
		p[7] = 64;
		Memory.copy (&p[8], &req[24], 16);
		Memory.copy (&p[24], &req[8], 16);

		size_t t = IPV6_HEADER_SIZE;
		Memory.copy (&p[t + 0], &req[t + 2], 2);
		Memory.copy (&p[t + 2], &req[t + 0], 2);
		put_uint32 (p, t + 4, PEER_ISN + seq_offset);
		put_uint32 (p, t + 8, get_uint32 (req, t + 4) + 1);
		p[t + 12] = (uint8) ((TCP_HEADER_SIZE / 4) << 4);
		p[t + 13] = flags;
		p[t + 14] = 0xff;
		p[t + 15] = 0xff;

		uint16 checksum = compute_tcp_checksum (p);
		p[t + 16] = (uint8) (checksum >> 8);
		p[t + 17] = (uint8) checksum;

		return new Bytes (p);
	}

	private uint16 compute_tcp_checksum (uint8[] packet) {
		size_t segment_size = packet.length - IPV6_HEADER_SIZE;

		uint32 sum = 0;
		for (size_t i = 8; i != IPV6_HEADER_SIZE; i += 2)
			sum += (packet[i] << 8) | packet[i + 1];
		sum += (uint32) segment_size;
		sum += 6;
		for (size_t i = IPV6_HEADER_SIZE; i < packet.length; i += 2) {
			uint8 lo = (i + 1 < packet.length) ? packet[i + 1] : 0;
			sum += (packet[i] << 8) | lo;
		}

		while ((sum >> 16) != 0)
			sum = (sum & 0xffff) + (sum >> 16);

		return (uint16) ~sum;
	}

	private uint32 get_uint32 (uint8[] buf, size_t offset) {
		return ((uint32) buf[offset] << 24) | ((uint32) buf[offset + 1] << 16) | ((uint32) buf[offset + 2] << 8) |
			buf[offset + 3];
	}

	private void put_uint32 (uint8[] buf, size_t offset, uint32 val) {
		buf[offset + 0] = (uint8) (val >> 24);
		buf[offset + 1] = (uint8) (val >> 16);
		buf[offset + 2] = (uint8) (val >> 8);
		buf[offset + 3] = (uint8) val;
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
