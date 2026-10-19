using Efni;

namespace Idun {
	[DBus (name = "org.freedesktop.Idun1.Daemon")]
	public interface DaemonService : Object {
		public abstract uint protocol_version {
			get;
		}

		public abstract bool autospawned {
			get;
		}

		public signal void device_attached (HashTable<string, Variant> description);
		public signal void device_detached (string udid);

		public abstract async HashTable<string, Variant>[] enumerate_devices (Cancellable? cancellable, BusName? sender)
			throws GLib.Error;
		public abstract async HashTable<string, Variant> open_tunnel (string udid, Cancellable? cancellable, BusName? sender)
			throws GLib.Error;
#if WINDOWS
		public abstract async uint8[] open_tcp_connection (string udid, uint16 port, uint client_pid, Cancellable? cancellable,
			BusName? sender) throws GLib.Error;
		public abstract uint8[] open_udp_socket (string udid, uint client_pid, out string local_address, out uint16 local_port,
			Cancellable? cancellable, BusName? sender) throws GLib.Error;
#else
		public abstract async Socket open_tcp_connection (string udid, uint16 port, Cancellable? cancellable, BusName? sender)
			throws GLib.Error;
		public abstract Socket open_udp_socket (string udid, out string local_address, out uint16 local_port,
			Cancellable? cancellable, BusName? sender) throws GLib.Error;
#endif
		public abstract async void shutdown (Cancellable? cancellable, BusName? sender) throws GLib.Error;
	}

	namespace Daemon {
		public const uint PROTOCOL_VERSION = 1;
		public const string BUS_NAME = "org.freedesktop.Idun1";
		public const string OBJECT_PATH = "/org/freedesktop/Idun1";

#if WINDOWS
		private const string FILENAME = "idund.exe";
#else
		private const string FILENAME = "idund";
#endif

		public string query_control_path () {
			return Path.build_filename (query_runtime_directory (), "control");
		}

		public string query_runtime_directory () {
#if WINDOWS
			return Path.build_filename (Environment.get_user_cache_dir (), "idun");
#else
			unowned string? runtime_dir = Environment.get_variable ("XDG_RUNTIME_DIR");
			if (runtime_dir != null)
				return Path.build_filename (runtime_dir, "idun");
			return Path.build_filename (Environment.get_tmp_dir (), "idun-%u".printf ((uint) Posix.getuid ()));
#endif
		}

		public string? read_endpoint_address (string control_path) {
#if WINDOWS
			string address;
			try {
				FileUtils.get_contents (control_path, out address);
			} catch (FileError e) {
				return null;
			}
			return address;
#else
			if (!FileUtils.test (control_path, EXISTS))
				return null;
			return "unix:path=" + DBus.address_escape_value (control_path);
#endif
		}

		public string query_installed_path () {
			string module_dir = Path.get_dirname (_query_library_path ());

			string basename = Path.get_basename (module_dir);
			if (basename == "bin" || basename == "sbin")
				return Path.build_filename (module_dir, FILENAME);

			string prefix = module_dir.has_suffix (Config.LIBDIR)
				? module_dir[:module_dir.length - Config.LIBDIR.length]
				: Path.get_dirname (module_dir);
			return Path.build_filename (prefix, Config.BINDIR, FILENAME);
		}

		public extern string _query_library_path ();

		public HashTable<string, Variant> describe_device (Device device) {
			var description = new HashTable<string, Variant> (str_hash, str_equal);
			description["udid"] = device.udid;
			description["connection-type"] = Marshal.enum_to_nick<ConnectionType> (device.connection_type);
			description["name"] = device.name;
			Variant? icon = device.icon;
			if (icon != null)
				description["icon"] = icon;
			return description;
		}

		public HashTable<string, Variant> describe_tunnel (Tunnel tunnel) {
			var description = new HashTable<string, Variant> (str_hash, str_equal);
			description["remote-address"] = tunnel.make_remote_address (0).get_address ().to_string ();
			description["rsd-port"] = tunnel.rsd_port;
			description["opened-at"] = tunnel.opened_at;
			Bytes? key = tunnel.remote_unlock_host_key;
			if (key != null)
				description["remote-unlock-host-key"] = new Variant.from_bytes (VariantType.BYTESTRING, key, true);

			var netstack = tunnel.netstack;
			description["local-address"] = netstack.listener_ip.to_string ();
			description["scope-id"] = (uint32) netstack.scope_id;
			description["transport"] = (netstack is LwipNetworkStack) ? "relay" : "direct";

			return description;
		}

#if WINDOWS
		public uint8[] hand_over_socket (Socket socket, uint process_id) throws Efni.Error {
			var info = _duplicate_socket (socket, process_id);
			try {
				socket.close ();
			} catch (GLib.Error e) {
			}
			return info;
		}

		public extern uint8[] _duplicate_socket (Socket socket, uint process_id) throws Efni.Error;

		public extern Socket _socket_from_duplicate (uint8[] info) throws Efni.Error;

		public extern uint _query_process_id ();

		public extern InputStream _spawn (string path) throws Efni.Error;
#endif

		[NoReturn]
		public void throw_remote_error (GLib.Error e) throws Efni.Error, IOError {
			DBusError.strip_remote_error (e);

			if (e is Efni.Error)
				throw (Efni.Error) e;

			if (e is IOError.CANCELLED)
				throw (IOError) e;

			throw new Efni.Error.TRANSPORT ("%s", e.message);
		}
	}
}
