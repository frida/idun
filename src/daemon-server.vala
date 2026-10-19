using Efni;

namespace Idun {
	public sealed class DaemonServer : Object {
		public signal void idle ();

		public SocketAddress endpoint {
			get;
			construct;
		}

		public bool autospawned {
			get;
			construct;
		}

		public uint idle_timeout {
			get;
			construct;
		}

		public bool serve_session_bus {
			get;
			construct;
		}

		private DeviceMonitor monitor = new DeviceMonitor.for_daemon ();
		private Gee.Map<string, Device> devices = new Gee.HashMap<string, Device> ();
		private Gee.Map<string, Tunnel> tunnels = new Gee.HashMap<string, Tunnel> ();
		private SocketService service = new SocketService ();
		private Gee.Set<DBusConnection> clients = new Gee.HashSet<DBusConnection> ();
		private Gee.Map<string, uint> bus_clients = new Gee.HashMap<string, uint> ();
		private uint bus_name_id;
		private Gee.Set<UdpRelay> udp_relays = new Gee.HashSet<UdpRelay> ();
		private DaemonService service_impl;
		private Source? idle_source;
		private Cancellable io_cancellable = new Cancellable ();

		public DaemonServer (SocketAddress endpoint, bool autospawned, uint idle_timeout, bool serve_session_bus) {
			Object (
				endpoint: endpoint,
				autospawned: autospawned,
				idle_timeout: idle_timeout,
				serve_session_bus: serve_session_bus
			);
		}

		construct {
			service_impl = new DaemonServiceImpl (this);
		}

		public async void start (Cancellable? cancellable) throws Efni.Error, IOError {
			prepare_endpoint ();

			monitor.device_attached.connect (on_device_attached);
			monitor.device_detached.connect (on_device_detached);
			yield monitor.start (cancellable);

			try {
				SocketAddress effective_address;
				service.add_address (endpoint, STREAM, DEFAULT, null, out effective_address);
			} catch (GLib.Error e) {
				throw new Efni.Error.ADDRESS_IN_USE ("%s", e.message);
			}
			service.incoming.connect (on_incoming);
			service.start ();

			if (serve_session_bus && Environment.get_variable ("DBUS_SESSION_BUS_ADDRESS") != null)
				bus_name_id = Bus.own_name (SESSION, Daemon.BUS_NAME, NONE, on_bus_acquired);

			schedule_idle_check ();
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			cancel_idle_check ();

			if (bus_name_id != 0) {
				Bus.unown_name (bus_name_id);
				bus_name_id = 0;
			}
			foreach (var watch_id in bus_clients.values)
				Bus.unwatch_name (watch_id);
			bus_clients.clear ();

			stop_listening ();
			io_cancellable.cancel ();

			foreach (var client in clients.to_array ()) {
				try {
					yield client.close (cancellable);
				} catch (GLib.Error e) {
					cancellable.set_error_if_cancelled ();
				}
			}

			yield monitor.stop (cancellable);
		}

		private void stop_listening () {
			service.stop ();
			remove_endpoint ();
		}

		private void prepare_endpoint () throws Efni.Error {
			var address = endpoint as UnixSocketAddress;
			if (address == null)
				return;

			var path = File.new_for_path (address.path);
			try {
				path.get_parent ().make_directory_with_parents ();
			} catch (GLib.Error e) {
				if (!(e is IOError.EXISTS))
					throw new Efni.Error.PERMISSION_DENIED ("%s", e.message);
			}
			FileUtils.chmod (path.get_parent ().get_path (), 0700);

			if (!path.query_exists ())
				return;

			SocketConnection? probe = null;
			try {
				probe = new SocketClient ().connect (address);
			} catch (GLib.Error e) {
			}
			if (probe != null) {
				try {
					probe.close ();
				} catch (GLib.Error e) {
				}
				throw new Efni.Error.ADDRESS_IN_USE ("idund is already running");
			}

			FileUtils.unlink (address.path);
		}

		private void remove_endpoint () {
			var address = endpoint as UnixSocketAddress;
			if (address != null)
				FileUtils.unlink (address.path);
		}

		private bool on_incoming (SocketConnection connection) {
			serve.begin (connection);
			return true;
		}

		private async void serve (SocketConnection stream) {
			try {
				var connection = yield new DBusConnection (stream, DBus.generate_guid (),
					AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS | DELAY_MESSAGE_PROCESSING, null, io_cancellable);
				connection.register_object (Daemon.OBJECT_PATH, service_impl);
				connection.on_closed.connect (on_client_closed);
				clients.add (connection);
				cancel_idle_check ();
				connection.start_message_processing ();
			} catch (GLib.Error e) {
			}
		}

		private void on_client_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			clients.remove (connection);
			schedule_idle_check ();
		}

		private void on_bus_acquired (DBusConnection connection) {
			try {
				connection.register_object (Daemon.OBJECT_PATH, service_impl);
			} catch (IOError e) {
			}
		}

		private void track_bus_client (BusName? sender) {
			if (sender == null || bus_clients.has_key (sender))
				return;

			bus_clients[sender] = Bus.watch_name (SESSION, sender, NONE, null, on_bus_client_vanished);
			cancel_idle_check ();
		}

		private void on_bus_client_vanished (DBusConnection connection, string name) {
			uint watch_id;
			if (bus_clients.unset (name, out watch_id))
				Bus.unwatch_name (watch_id);
			schedule_idle_check ();
		}

		private void schedule_idle_check () {
			if (idle_timeout == 0 || !clients.is_empty || !bus_clients.is_empty || idle_source != null)
				return;

			var source = new TimeoutSource.seconds (idle_timeout);
			source.set_callback (() => {
				idle_source = null;
				idle ();
				return Source.REMOVE;
			});
			source.attach (MainContext.get_thread_default ());
			idle_source = source;
		}

		private void cancel_idle_check () {
			if (idle_source == null)
				return;
			idle_source.destroy ();
			idle_source = null;
		}

		private void on_device_attached (Device device) {
			devices[device.udid] = device;
			service_impl.device_attached (Daemon.describe_device (device));
		}

		private void on_device_detached (Device device) {
			unowned string udid = device.udid;
			devices.unset (udid);
			tunnels.unset (udid);
			service_impl.device_detached (udid);
		}

		private HashTable<string, Variant>[] enumerate_devices () {
			var result = new HashTable<string, Variant>[devices.size];
			int i = 0;
			foreach (var device in devices.values)
				result[i++] = Daemon.describe_device (device);
			return result;
		}

		private async Tunnel open_tunnel (string udid, Cancellable? cancellable) throws Efni.Error, IOError {
			var device = devices[udid];
			if (device == null)
				throw new Efni.Error.INVALID_ARGUMENT ("Device not found");

			var tunnel = yield device.find_tunnel (cancellable);
			if (tunnel == null)
				throw new Efni.Error.NOT_SUPPORTED ("Tunnel not available");

			tunnels[udid] = tunnel;
			return tunnel;
		}

		private async Socket open_tcp_connection (string udid, uint16 port, Cancellable? cancellable) throws Efni.Error, IOError {
			var tunnel = yield open_tunnel (udid, cancellable);
			var stream = yield tunnel.open_tcp_connection (port, cancellable);

			Socket ours, theirs;
			make_socket_pair (STREAM, out ours, out theirs);

			relay_stream.begin (SocketConnection.factory_create_connection (ours), stream);

			return theirs;
		}

		private async void relay_stream (IOStream a, IOStream b) {
			try {
				yield a.splice_async (b, CLOSE_STREAM1 | CLOSE_STREAM2 | WAIT_FOR_BOTH, Priority.DEFAULT, io_cancellable);
			} catch (GLib.Error e) {
			}
		}

		private Socket open_udp_socket (string udid, out string local_address, out uint16 local_port) throws Efni.Error {
			var tunnel = get_tunnel (udid);
			var socket = tunnel.create_udp_socket ();

			var address = socket.get_local_address ();
			local_address = address.get_address ().to_string ();
			local_port = address.get_port ();

			Socket ours, theirs;
			make_socket_pair (DATAGRAM, out ours, out theirs);

			var relay = new UdpRelay (ours, socket, tunnel, io_cancellable);
			relay.closed.connect (on_udp_relay_closed);
			udp_relays.add (relay);

			return theirs;
		}

		private void on_udp_relay_closed (UdpRelay relay) {
			udp_relays.remove (relay);
		}

		private Tunnel get_tunnel (string udid) throws Efni.Error {
			var tunnel = tunnels[udid];
			if (tunnel == null)
				throw new Efni.Error.INVALID_OPERATION ("Tunnel not open");
			return tunnel;
		}

		private static void make_socket_pair (SocketType type, out Socket ours, out Socket theirs) throws Efni.Error {
			int fds[2];
			if (Posix.socketpair (Posix.AF_UNIX, (type == STREAM) ? Posix.SOCK_STREAM : Posix.SOCK_DGRAM, 0, fds) != 0)
				throw new Efni.Error.NOT_SUPPORTED ("%s", strerror (errno));

			try {
				ours = new Socket.from_fd (fds[0]);
				theirs = new Socket.from_fd (fds[1]);
			} catch (GLib.Error e) {
				throw new Efni.Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		private async void shutdown () {
			foreach (var client in clients.to_array ()) {
				try {
					yield client.flush (null);
				} catch (GLib.Error e) {
				}
			}

			try {
				yield stop (null);
			} catch (IOError e) {
			}
			idle ();
		}

		private class DaemonServiceImpl : Object, DaemonService {
			public uint protocol_version {
				get {
					return Daemon.PROTOCOL_VERSION;
				}
			}

			public bool autospawned {
				get {
					return server.autospawned;
				}
			}

			private weak DaemonServer server;

			public DaemonServiceImpl (DaemonServer server) {
				this.server = server;
			}

			public async HashTable<string, Variant>[] enumerate_devices (Cancellable? cancellable, BusName? sender)
					throws GLib.Error {
				server.track_bus_client (sender);
				return server.enumerate_devices ();
			}

			public async HashTable<string, Variant> open_tunnel (string udid, Cancellable? cancellable, BusName? sender)
					throws GLib.Error {
				server.track_bus_client (sender);
				return Daemon.describe_tunnel (yield server.open_tunnel (udid, cancellable));
			}

			public async Socket open_tcp_connection (string udid, uint16 port, Cancellable? cancellable, BusName? sender)
					throws GLib.Error {
				server.track_bus_client (sender);
				return yield server.open_tcp_connection (udid, port, cancellable);
			}

			public Socket open_udp_socket (string udid, out string local_address, out uint16 local_port, Cancellable? cancellable,
					BusName? sender) throws GLib.Error {
				server.track_bus_client (sender);
				return server.open_udp_socket (udid, out local_address, out local_port);
			}

			public async void shutdown (Cancellable? cancellable, BusName? sender) throws GLib.Error {
				server.stop_listening ();
				Idle.add (() => {
					server.shutdown.begin ();
					return Source.REMOVE;
				});
			}
		}

		private class UdpRelay : Object {
			public signal void closed ();

			private Socket client;
			private UdpSocket device;
			private Tunnel tunnel;
			private Cancellable cancellable;
			private Source client_source;
			private Source device_source;
			private uint8[] buffer = new uint8[65536];

			public UdpRelay (Socket client, UdpSocket device, Tunnel tunnel, Cancellable cancellable) {
				this.client = client;
				this.device = device;
				this.tunnel = tunnel;
				this.cancellable = cancellable;

				client.blocking = false;

				var main_context = MainContext.get_thread_default ();

				var client_src = client.create_source (IOCondition.IN, cancellable);
				client_src.set_callback (on_client_readable);
				client_src.attach (main_context);
				client_source = client_src;

				var device_src = device.datagram_based.create_source (IOCondition.IN, cancellable);
				device_src.set_callback (on_device_readable);
				device_src.attach (main_context);
				device_source = device_src;
			}

			private bool on_client_readable (Socket socket, IOCondition condition) {
				if ((condition & (IOCondition.HUP | IOCondition.ERR)) != 0) {
					close ();
					return Source.REMOVE;
				}

				try {
					ssize_t n = client.receive (buffer, cancellable);
					var reader = new BufferReader (new Buffer (new Bytes (buffer[:n]), BIG_ENDIAN));
					uint16 port = reader.read_uint16 ();
					Udp.send_to (reader.read_remaining_data (), tunnel.make_remote_address (port), device.datagram_based,
						cancellable);
				} catch (GLib.Error e) {
					close ();
					return Source.REMOVE;
				}

				return Source.CONTINUE;
			}

			private bool on_device_readable (DatagramBased datagram_based, IOCondition condition) {
				try {
					InetSocketAddress sender;
					size_t n = Udp.recv (buffer, datagram_based, cancellable, out sender);
					var frame = new BufferBuilder (BIG_ENDIAN)
						.append_uint16 (sender.get_port ())
						.append_data (buffer[:n])
						.build ();
					Udp.send (frame.get_data (), client, cancellable);
				} catch (GLib.Error e) {
					close ();
					return Source.REMOVE;
				}

				return Source.CONTINUE;
			}

			private void close () {
				client_source.destroy ();
				device_source.destroy ();
				try {
					client.close ();
				} catch (GLib.Error e) {
				}
				closed ();
			}
		}
	}
}
