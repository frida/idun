using Efni;

namespace Idun {
	public sealed class TunNetworkStack : Object, NetworkStack, VirtualNetworkStack {
		public Bytes? ethernet_address {
			get;
			construct;
		}

		public InetAddress? ipv6_address {
			get;
			construct;
		}

		public InetAddress listener_ip {
			get {
				return system.listener_ip;
			}
		}

		public uint scope_id {
			get {
				return system.scope_id;
			}
		}

		public uint16 mtu {
			get;
			construct;
		}

		private State state = STARTED;

		private UnixInputStream input;
		private UnixOutputStream output;
		private size_t frame_size;
		private SystemNetworkStack system;

		private Cancellable io_cancellable = new Cancellable ();

		private const string DEVICE_PATH = "/dev/net/tun";
		private const string INTERFACE_NAME_TEMPLATE = "idun%d";
		private const uint8 PREFIX_LENGTH = 64;
		private const size_t ETHERNET_HEADER_SIZE = 14;

		private enum State {
			STARTED,
			STOPPED
		}

		public TunNetworkStack (Bytes? ethernet_address, InetAddress? ipv6_address, uint16 mtu) throws Efni.Error {
			Object (
				ethernet_address: ethernet_address,
				ipv6_address: ipv6_address,
				mtu: mtu
			);

			bool ethernet = ethernet_address != null;

			int fd = Posix.open (DEVICE_PATH, Posix.O_RDWR);
			if (fd == -1)
				throw new Efni.Error.NOT_SUPPORTED ("Unable to open %s: %s", DEVICE_PATH, strerror (errno));
			Posix.fcntl (fd, Posix.F_SETFD, Posix.FD_CLOEXEC);
			input = new UnixInputStream (fd, true);
			output = new UnixOutputStream (fd, false);

			uint8[] request = new BufferBuilder ()
				.append_string (INTERFACE_NAME_TEMPLATE)
				.seek (Linux.Network.INTERFACE_NAME_SIZE)
				.append_int16 ((int16) ((ethernet ? Linux.If.IFF_TAP : Linux.If.IFF_TUN) | Linux.If.IFF_NO_PI))
				.seek (sizeof (Linux.Network.IfReq))
				.build ()
				.get_data ();
			if (Linux.ioctl (fd, Linux.If.TUNSETIFF, request) == -1)
				throw new Efni.Error.PERMISSION_DENIED ("Unable to create TUN interface: %s", strerror (errno));
			uint interface_index = Linux.Network.if_nametoindex ((string) request);

			InetAddress address = (ipv6_address != null) ? ipv6_address : make_link_local_address (ethernet_address);

			var netlink = new NetlinkSocket ();
			netlink.configure_link (interface_index, ethernet_address, mtu);
			netlink.add_address (interface_index, address, PREFIX_LENGTH);

			system = new SystemNetworkStack (address, ethernet ? interface_index : 0);
			frame_size = mtu + (ethernet ? ETHERNET_HEADER_SIZE : 0);

			process_outgoing_datagrams.begin ();
		}

		public override void dispose () {
			stop ();

			base.dispose ();
		}

		public void stop () {
			if (state == STOPPED)
				return;
			io_cancellable.cancel ();
			state = STOPPED;
		}

		public async IOStream open_tcp_connection (InetSocketAddress address, Cancellable? cancellable) throws Efni.Error, IOError {
			return yield system.open_tcp_connection (address, cancellable);
		}

		public UdpSocket create_udp_socket () throws Efni.Error {
			return system.create_udp_socket ();
		}

		public async void handle_incoming_datagrams (Gee.Collection<Bytes> datagrams) throws Efni.Error {
			foreach (var datagram in datagrams) {
				try {
					output.write_all (datagram.get_data (), null, io_cancellable);
				} catch (GLib.Error e) {
					throw new Efni.Error.TRANSPORT ("%s", e.message);
				}
			}
		}

		private async void process_outgoing_datagrams () {
			var buffer = new uint8[frame_size];
			try {
				while (true) {
					var datagrams = new Gee.ArrayList<Bytes> ();
					datagrams.add (yield input.read_bytes_async (frame_size, Priority.DEFAULT, io_cancellable));
					while (true) {
						ssize_t n;
						try {
							n = input.read_nonblocking (buffer, io_cancellable);
						} catch (IOError e) {
							if (e is IOError.WOULD_BLOCK)
								break;
							throw e;
						}
						datagrams.add (new Bytes (buffer[:n]));
					}
					outgoing_datagrams (datagrams);
				}
			} catch (GLib.Error e) {
			}

			try {
				input.close ();
			} catch (IOError e) {
			}
		}

		private static InetAddress make_link_local_address (Bytes ethernet_address) {
			unowned uint8[] mac = ethernet_address.get_data ();

			var address = new uint8[16];
			address[0] = 0xfe;
			address[1] = 0x80;
			address[8] = mac[0] ^ 0x02;
			address[9] = mac[1];
			address[10] = mac[2];
			address[11] = 0xff;
			address[12] = 0xfe;
			address[13] = mac[3];
			address[14] = mac[4];
			address[15] = mac[5];

			return new InetAddress.from_bytes (address, IPV6);
		}

		private class NetlinkSocket {
			private int fd;
			private uint32 next_seq = 1;

			private const size_t HEADER_SIZE = 16;
			private const uint16 IFLA_ADDRESS = 1;
			private const uint16 IFLA_MTU = 4;
			private const uint16 IFA_ADDRESS = 1;
			private const uint8 IFA_F_NODAD = 0x02;
			private const uint8 IFA_F_PERMANENT = 0x80;

			public NetlinkSocket () throws Efni.Error {
				fd = Posix.socket (Linux.Socket.AF_NETLINK, Posix.SOCK_RAW, Linux.Netlink.NETLINK_ROUTE);
				if (fd == -1)
					throw new Efni.Error.NOT_SUPPORTED ("Unable to open netlink socket: %s", strerror (errno));
				Posix.fcntl (fd, Posix.F_SETFD, Posix.FD_CLOEXEC);
			}

			~NetlinkSocket () {
				Posix.close (fd);
			}

			public void configure_link (uint index, Bytes? address, uint16 mtu) throws Efni.Error {
				var body = new BufferBuilder ()
					.append_uint8 ((uint8) Posix.AF_UNSPEC)
					.append_uint8 (0)
					.append_uint16 (0)
					.append_int32 ((int32) index)
					.append_uint32 (Linux.Network.IfFlag.UP)
					.append_uint32 (Linux.Network.IfFlag.UP);
				if (address != null)
					append_attribute (body, IFLA_ADDRESS, address.get_data ());
				append_attribute (body, IFLA_MTU, new BufferBuilder ().append_uint32 (mtu).build ().get_data ());

				execute ((uint16) Linux.Netlink.RtMessageType.NEWLINK, Linux.Netlink.NLM_F_REQUEST | Linux.Netlink.NLM_F_ACK, body.build ());
			}

			public void add_address (uint index, InetAddress address, uint8 prefix_length) throws Efni.Error {
				var body = new BufferBuilder ()
					.append_uint8 ((uint8) Posix.AF_INET6)
					.append_uint8 (prefix_length)
					.append_uint8 (IFA_F_NODAD | IFA_F_PERMANENT)
					.append_uint8 (0)
					.append_uint32 (index);
				var raw_address = new uint8[address.get_native_size ()];
				Memory.copy (raw_address, address.to_bytes (), raw_address.length);
				append_attribute (body, IFA_ADDRESS, raw_address);

				execute ((uint16) Linux.Netlink.RtMessageType.NEWADDR,
					Linux.Netlink.NLM_F_REQUEST | Linux.Netlink.NLM_F_ACK | Linux.Netlink.NLM_F_EXCL | Linux.Netlink.NLM_F_CREATE,
					body.build ());
			}

			private static void append_attribute (BufferBuilder builder, uint16 type, uint8[] data) {
				builder
					.append_uint16 ((uint16) (4 + data.length))
					.append_uint16 (type)
					.append_data (data)
					.align (4);
			}

			private void execute (uint16 type, int flags, Bytes body) throws Efni.Error {
				var request = new BufferBuilder ()
					.append_uint32 ((uint32) (HEADER_SIZE + body.get_size ()))
					.append_uint16 (type)
					.append_uint16 ((uint16) flags)
					.append_uint32 (next_seq++)
					.append_uint32 (0)
					.append_bytes (body)
					.build ();
				unowned uint8[] data = request.get_data ();
				if (Posix.write (fd, data, data.length) != data.length)
					throw new Efni.Error.TRANSPORT ("Unable to send netlink request: %s", strerror (errno));

				var response = new uint8[4096];
				ssize_t n = Posix.read (fd, response, response.length);
				if (n == -1)
					throw new Efni.Error.TRANSPORT ("Unable to read netlink response: %s", strerror (errno));

				var reader = new BufferReader (new Buffer (new Bytes (response[:n])));
				reader.skip (4);
				uint16 response_type = reader.read_uint16 ();
				reader.skip (10);
				if (response_type == Linux.Netlink.NLMSG_ERROR) {
					int32 error = reader.read_int32 ();
					if (error != 0)
						throw new Efni.Error.PERMISSION_DENIED ("Unable to configure TUN interface: %s", strerror (-error));
				}
			}
		}
	}
}
