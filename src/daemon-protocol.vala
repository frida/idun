using Efni;

namespace Idun {
	public enum DaemonPolicy {
		AUTO,
		NEVER;

		public static DaemonPolicy from_environment () {
			unowned string? nick = Environment.get_variable ("IDUN_DAEMON");
			if (nick == null)
				return AUTO;
			try {
				return Marshal.enum_from_nick<DaemonPolicy> (nick);
			} catch (Efni.Error e) {
				return AUTO;
			}
		}
	}

	[DBus (name = "io.github.frida.Idun1.Daemon")]
	public interface DaemonService : Object {
		public abstract uint protocol_version {
			get;
		}

		public abstract bool autospawned {
			get;
		}

		public signal void device_attached (HashTable<string, Variant> description);
		public signal void device_detached (string udid);

		public abstract async HashTable<string, Variant>[] enumerate_devices (Cancellable? cancellable) throws GLib.Error;
		public abstract async HashTable<string, Variant> open_tunnel (string udid, Cancellable? cancellable) throws GLib.Error;
		public abstract async Socket open_tcp_connection (string udid, uint16 port, Cancellable? cancellable) throws GLib.Error;
		public abstract Socket open_udp_socket (string udid, out string local_address, out uint16 local_port,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async void shutdown (Cancellable? cancellable) throws GLib.Error;
	}

	namespace Daemon {
		public const uint PROTOCOL_VERSION = 1;
		public const string OBJECT_PATH = "/io/github/frida/Idun1/Daemon";

		public SocketAddress query_endpoint () throws Efni.Error {
			return new UnixSocketAddress (Path.build_filename (query_runtime_directory ().get_path (), "control"));
		}

		public File query_runtime_directory () throws Efni.Error {
			unowned string? runtime_dir = Environment.get_variable ("XDG_RUNTIME_DIR");
			if (runtime_dir != null)
				return File.new_build_filename (runtime_dir, "idun");
			return File.new_build_filename (Environment.get_tmp_dir (), "idun-%u".printf ((uint) Posix.getuid ()));
		}

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
			return description;
		}

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
