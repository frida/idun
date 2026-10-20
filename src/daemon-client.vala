using Efni;

namespace Idun {
	public delegate string DaemonLocator () throws Efni.Error;

	public sealed class DaemonClient : Object {
		public DaemonService service {
			get;
			construct;
		}

		public DBusConnection connection {
			get;
			construct;
		}

		private const uint SPAWN_TIMEOUT = 10000;

		public static async DaemonClient open_shared (DaemonLocator? locate_daemon, Cancellable? cancellable)
				throws Efni.Error, IOError {
			var client = yield try_open_session_bus (cancellable);
			if (client == null) {
				client = yield try_open_control_path (cancellable);
				if (client == null) {
					yield spawn ((locate_daemon != null) ? locate_daemon () : Daemon.query_installed_path (), cancellable);
					client = yield try_open_control_path (cancellable);
					if (client == null)
						throw new Efni.Error.SERVER_NOT_RUNNING ("idund did not start listening");
				}
			}

			if (client.service.protocol_version == Daemon.PROTOCOL_VERSION)
				return client;

			if (!client.service.autospawned)
				throw new Efni.Error.NOT_SUPPORTED ("Incompatible idund is running; please restart it");

			try {
				yield client.service.shutdown (cancellable, null);
			} catch (GLib.Error e) {
			}
			yield client.close (cancellable);

			return yield open_shared (locate_daemon, cancellable);
		}

		public static async DaemonClient open_endpoint (string address, Cancellable? cancellable) throws Efni.Error, IOError {
			var client = yield try_open_endpoint (address, cancellable);
			if (client == null)
				throw new Efni.Error.SERVER_NOT_RUNNING ("idund is not running");
			return client;
		}

		private DaemonClient (DBusConnection connection, DaemonService service) {
			Object (connection: connection, service: service);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			try {
				yield connection.close (cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED)
					throw (IOError) e;
			}
		}

		private static async DaemonClient? try_open_session_bus (Cancellable? cancellable) throws IOError {
			if (Environment.get_variable ("DBUS_SESSION_BUS_ADDRESS") == null)
				return null;

			try {
				var connection = yield Bus.get (SESSION, cancellable);
				DaemonService service = yield connection.get_proxy (Daemon.BUS_NAME, Daemon.OBJECT_PATH, DBusProxyFlags.NONE,
					cancellable);
				if (((DBusProxy) service).get_name_owner () == null)
					return null;
				return new DaemonClient (connection, service);
			} catch (GLib.Error e) {
				cancellable.set_error_if_cancelled ();
				return null;
			}
		}

		private static async DaemonClient? try_open_control_path (Cancellable? cancellable) throws Efni.Error, IOError {
			string? address = Daemon.read_endpoint_address (Daemon.query_control_path ());
			if (address == null)
				return null;
			return yield try_open_endpoint (address, cancellable);
		}

		private static async DaemonClient? try_open_endpoint (string address, Cancellable? cancellable) throws Efni.Error, IOError {
			DBusConnection connection;
			try {
				connection = yield new DBusConnection.for_address (address, AUTHENTICATION_CLIENT, null, cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED)
					throw (IOError) e;
				return null;
			}

			try {
				DaemonService service = yield connection.get_proxy (null, Daemon.OBJECT_PATH, DBusProxyFlags.NONE, cancellable);
				return new DaemonClient (connection, service);
			} catch (GLib.Error e) {
				Daemon.throw_remote_error (e);
			}
		}

		private static async void spawn (string path, Cancellable? cancellable) throws Efni.Error, IOError {
#if WINDOWS
			var output = new DataInputStream (Daemon._spawn (path));
#else
			Subprocess process;
			try {
				process = new Subprocess (STDOUT_PIPE, path, "--background");
			} catch (GLib.Error e) {
				throw new Efni.Error.NOT_SUPPORTED ("Unable to start idund: %s", e.message);
			}

			var output = new DataInputStream (process.get_stdout_pipe ());
#endif
			output.newline_type = ANY;
			var timeout = new Cancellable ();
			var timeout_source = new TimeoutSource (SPAWN_TIMEOUT);
			timeout_source.set_callback (() => {
				timeout.cancel ();
				return Source.REMOVE;
			});
			timeout_source.attach (MainContext.get_thread_default ());
			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				timeout.cancel ();
				return Source.REMOVE;
			});
			cancel_source.attach (MainContext.get_thread_default ());

			try {
				string? line = yield output.read_line_async (Priority.DEFAULT, timeout);
				if (line != "ready")
					throw new Efni.Error.NOT_SUPPORTED ("Unable to start idund: %s", (line != null) ? line : "exited early");
			} catch (IOError e) {
				cancellable.set_error_if_cancelled ();
				throw new Efni.Error.TIMED_OUT ("Timed out waiting for idund to start");
			} finally {
				timeout_source.destroy ();
				cancel_source.destroy ();
			}
		}
	}

	public sealed class DaemonCoreDeviceBackend : Object, Backend {
		public DaemonClient client {
			get;
			construct;
		}

		private Gee.Map<string, DaemonTransport> transports = new Gee.HashMap<string, DaemonTransport> ();

		public DaemonCoreDeviceBackend (DaemonClient client) {
			Object (client: client);
		}

		public async void start (Cancellable? cancellable) throws IOError {
			var service = client.service;
			service.device_attached.connect (on_device_attached);
			service.device_detached.connect (on_device_detached);

			try {
				foreach (var description in yield service.enumerate_devices (cancellable, null))
					on_device_attached (description);
			} catch (GLib.Error e) {
				cancellable.set_error_if_cancelled ();
			}
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			foreach (var transport in transports.values.to_array ())
				transport_detached (transport);
			transports.clear ();

			yield client.close (cancellable);
		}

		private void on_device_attached (HashTable<string, Variant> description) {
			var transport = new DaemonTransport (description, client.service);
			transports[transport.udid] = transport;
			transport_attached (transport);
		}

		private void on_device_detached (string udid) {
			DaemonTransport transport;
			if (transports.unset (udid, out transport))
				transport_detached (transport);
		}
	}

	private sealed class DaemonTransport : Object, Transport {
		public ConnectionType connection_type {
			get {
				return _connection_type;
			}
		}

		public string udid {
			get {
				return _udid;
			}
		}

		public string? name {
			get {
				return _name;
			}
		}

		public Variant? icon {
			get {
				return _icon;
			}
		}

		public UsbmuxDevice? usbmux_device {
			get {
				return null;
			}
		}

		private ConnectionType _connection_type;
		private string _udid;
		private string _name;
		private Variant? _icon;
		private DaemonService service;
		private Promise<Tunnel?>? tunnel_request;

		public DaemonTransport (HashTable<string, Variant> description, DaemonService service) {
			_udid = description["udid"].get_string ();
			_name = description["name"].get_string ();
			_icon = description["icon"];
			try {
				_connection_type = Marshal.enum_from_nick<ConnectionType> (description["connection-type"].get_string ());
			} catch (Efni.Error e) {
				_connection_type = NETWORK;
			}
			this.service = service;
		}

		public async Tunnel? find_tunnel (UsbmuxDevice? device, Cancellable? cancellable) throws Efni.Error, IOError {
			while (tunnel_request != null) {
				try {
					return yield tunnel_request.future.wait_async (cancellable);
				} catch (Efni.Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			tunnel_request = new Promise<Tunnel?> ();

			try {
				var tunnel = new DaemonTunnel (udid, service);
				yield tunnel.open (cancellable);

				tunnel_request.resolve (tunnel);

				return tunnel;
			} catch (GLib.Error e) {
				tunnel_request.reject (e);
				tunnel_request = null;

				throw_api_error (e);
			}
		}
	}

	private sealed class DaemonTunnel : Object, Tunnel {
		public string udid {
			get;
			construct;
		}

		public DaemonService service {
			get;
			construct;
		}

		public DiscoveryService discovery {
			get {
				return _discovery;
			}
		}

		public int64 opened_at {
			get {
				return _opened_at;
			}
		}

		public Bytes? remote_unlock_host_key {
			get {
				return _remote_unlock_host_key;
			}
		}

		public uint16 rsd_port {
			get {
				return _rsd_port;
			}
		}

		public NetworkStack netstack {
			get {
				return _netstack;
			}
		}

		private InetAddress remote_address;
		private uint16 _rsd_port;
		private int64 _opened_at;
		private Bytes? _remote_unlock_host_key;
		private NetworkStack? _netstack;
		private DiscoveryService? _discovery;

		public DaemonTunnel (string udid, DaemonService service) {
			Object (udid: udid, service: service);
		}

		public async void open (Cancellable? cancellable) throws Efni.Error, IOError {
			HashTable<string, Variant> description;
			try {
				description = yield service.open_tunnel (udid, cancellable, null);
			} catch (GLib.Error e) {
				Daemon.throw_remote_error (e);
			}

			remote_address = new InetAddress.from_string (description["remote-address"].get_string ());
			_rsd_port = description["rsd-port"].get_uint16 ();
			_opened_at = description["opened-at"].get_int64 ();
			Variant? key = description["remote-unlock-host-key"];
			if (key != null)
				_remote_unlock_host_key = key.get_data_as_bytes ();

			var local_address = new InetAddress.from_string (description["local-address"].get_string ());
			uint scope_id = description["scope-id"].get_uint32 ();
			if (description["transport"].get_string () == "direct")
				_netstack = new SystemNetworkStack (local_address, scope_id);
			else
				_netstack = new DaemonRelayNetworkStack (udid, service, local_address, scope_id, remote_address);

			_discovery = yield open_discovery_service (cancellable);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			_discovery.close ();
		}

		public async IOStream open_tcp_connection (uint16 port, Cancellable? cancellable) throws Efni.Error, IOError {
			return yield _netstack.open_tcp_connection (make_remote_address (port), cancellable);
		}

		public UdpSocket create_udp_socket () throws Efni.Error {
			var socket = _netstack.create_udp_socket ();
			socket.bind ((InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: _netstack.listener_ip,
				scope_id: _netstack.scope_id
			));
			return socket;
		}

		public InetSocketAddress make_remote_address (uint16 port) {
			return (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: remote_address,
				port: port,
				scope_id: _netstack.scope_id
			);
		}

		public async void refresh_discovery (Cancellable? cancellable) throws Efni.Error, IOError {
			var disco = yield open_discovery_service (cancellable);
			_discovery.close ();
			_discovery = disco;
		}

		private async DiscoveryService open_discovery_service (Cancellable? cancellable) throws Efni.Error, IOError {
			return yield DiscoveryService.open (yield open_tcp_connection (rsd_port, cancellable), cancellable);
		}
	}

	private sealed class DaemonRelayNetworkStack : Object, NetworkStack {
		public string udid {
			get;
			construct;
		}

		public DaemonService service {
			get;
			construct;
		}

		public InetAddress listener_ip {
			get {
				return _listener_ip;
			}
		}

		public uint scope_id {
			get {
				return _scope_id;
			}
		}

		private InetAddress _listener_ip;
		private uint _scope_id;
		private InetAddress remote_address;

		public DaemonRelayNetworkStack (string udid, DaemonService service, InetAddress listener_ip, uint scope_id,
				InetAddress remote_address) {
			Object (udid: udid, service: service);
			_listener_ip = listener_ip;
			_scope_id = scope_id;
			this.remote_address = remote_address;
		}

		public async IOStream open_tcp_connection (InetSocketAddress address, Cancellable? cancellable) throws Efni.Error, IOError {
			try {
#if WINDOWS
				var socket = Daemon._socket_from_duplicate (yield service.open_tcp_connection (udid, address.get_port (),
					Daemon._query_process_id (), cancellable, null));
#else
				var socket = yield service.open_tcp_connection (udid, address.get_port (), cancellable, null);
#endif
				return SocketConnection.factory_create_connection (socket);
			} catch (GLib.Error e) {
				Daemon.throw_remote_error (e);
			}
		}

		public UdpSocket create_udp_socket () throws Efni.Error {
			try {
				string local_address;
				uint16 local_port;
#if WINDOWS
				var socket = Daemon._socket_from_duplicate (service.open_udp_socket (udid, Daemon._query_process_id (),
					out local_address, out local_port, null, null));
#else
				var socket = service.open_udp_socket (udid, out local_address, out local_port, null, null);
#endif
				return new DaemonUdpSocket (socket, new InetSocketAddress.from_string (local_address, local_port),
					remote_address);
			} catch (GLib.Error e) {
				DBusError.strip_remote_error (e);
				if (e is Efni.Error)
					throw (Efni.Error) e;
				throw new Efni.Error.TRANSPORT ("%s", e.message);
			}
		}
	}

	private sealed class DaemonUdpSocket : Object, UdpSocket, DatagramBased {
		public DatagramBased datagram_based {
			get {
				return this;
			}
		}

		private Socket handle;
		private InetSocketAddress local_address;
		private InetAddress remote_address;
		private uint8[] rx_buffer = new uint8[65536];

		public DaemonUdpSocket (Socket handle, InetSocketAddress local_address, InetAddress remote_address) {
			this.handle = handle;
			this.local_address = local_address;
			this.remote_address = remote_address;

			handle.blocking = false;
		}

		public void bind (InetSocketAddress address) throws Efni.Error {
		}

		public InetSocketAddress get_local_address () throws Efni.Error {
			return local_address;
		}

		public void socket_connect (InetSocketAddress address, Cancellable? cancellable) throws Efni.Error {
			throw new Efni.Error.NOT_SUPPORTED ("Connected sockets are not supported");
		}

		public int datagram_receive_messages (InputMessage[] messages, int flags, int64 timeout, Cancellable? cancellable)
				throws GLib.Error {
			int received = 0;
			for (int i = 0; i != messages.length; i++) {
				InputMessage * message = &messages[i];
				ssize_t n;
				try {
					n = handle.receive (rx_buffer, cancellable);
				} catch (IOError e) {
					if (e is IOError.WOULD_BLOCK && received != 0)
						break;
					throw e;
				}

				var reader = new BufferReader (new Buffer (new Bytes (rx_buffer[:n]), BIG_ENDIAN));
				uint16 port = reader.read_uint16 ();
				unowned uint8[] payload = reader.read_remaining_data ();

				if (message->address != null)
					*message->address = new InetSocketAddress (remote_address, port);

				message->bytes_received = 0;
				message->flags = 0;

				uint8 * data = payload;
				size_t remaining = payload.length;
				foreach (unowned InputVector vector in message->vectors) {
					size_t chunk = size_t.min (remaining, vector.size);
					if (chunk == 0)
						break;
					Memory.copy (vector.buffer, data, chunk);
					data += chunk;
					remaining -= chunk;
					message->bytes_received += chunk;
				}

				received++;
			}
			return received;
		}

		public int datagram_send_messages (OutputMessage[] messages, int flags, int64 timeout, Cancellable? cancellable)
				throws GLib.Error {
			int sent = 0;
			for (int i = 0; i != messages.length; i++) {
				OutputMessage * message = &messages[i];
				var address = (InetSocketAddress) message->address;
				var frame = new BufferBuilder (BIG_ENDIAN)
					.append_uint16 (address.get_port ());
				foreach (unowned OutputVector vector in message->vectors) {
					unowned uint8[] data = (uint8[]) vector.buffer;
					frame.append_data (data[:vector.size]);
				}

				Bytes packet = frame.build ();
				try {
					handle.send (packet.get_data (), cancellable);
				} catch (IOError e) {
					if (e is IOError.WOULD_BLOCK && sent != 0)
						break;
					throw e;
				}
				message->bytes_sent = (uint) packet.get_size () - 2;

				sent++;
			}
			return sent;
		}

		public DatagramBasedSource datagram_create_source (IOCondition condition, Cancellable? cancellable) {
			return new DaemonUdpSocketSource (this, handle, condition, cancellable);
		}

		public IOCondition datagram_condition_check (IOCondition condition) {
			return handle.condition_check (condition);
		}

		public bool datagram_condition_wait (IOCondition condition, int64 timeout, Cancellable? cancellable) throws GLib.Error {
			return handle.condition_timed_wait (condition, timeout, cancellable);
		}
	}

	private class DaemonUdpSocketSource : DatagramBasedSource {
		public DaemonUdpSocket socket;
		public Socket handle;
		public IOCondition condition;

		public DaemonUdpSocketSource (DaemonUdpSocket socket, Socket handle, IOCondition condition, Cancellable? cancellable) {
			this.socket = socket;
			this.handle = handle;
			this.condition = condition;

			var handle_source = handle.create_source (condition, cancellable);
			handle_source.set_callback ((socket, condition) => Source.CONTINUE);
			add_child_source (handle_source);
		}

		protected override bool prepare (out int timeout) {
			timeout = -1;
			return (handle.condition_check (condition) & condition) != 0;
		}

		protected override bool check () {
			return (handle.condition_check (condition) & condition) != 0;
		}

		protected override bool dispatch (SourceFunc? callback) {
			if (callback == null)
				return Source.REMOVE;

			DatagramBasedSourceFunc f = (DatagramBasedSourceFunc) callback;
			return f (socket, handle.condition_check (condition));
		}
	}
}
