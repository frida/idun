using Efni;

namespace Idun {
	public interface NetworkStack : Object {
		public abstract InetAddress listener_ip {
			get;
		}

		public abstract uint scope_id {
			get;
		}

		public abstract async IOStream open_tcp_connection (InetSocketAddress address, Cancellable? cancellable)
			throws Efni.Error, IOError;

		public async IOStream open_tcp_connection_with_timeout (InetSocketAddress address, uint timeout, Cancellable? cancellable)
				throws Efni.Error, IOError {
			bool timed_out = false;
			var open_cancellable = new Cancellable ();

			var main_context = MainContext.get_thread_default ();

			var timeout_source = new TimeoutSource (timeout);
			timeout_source.set_callback (() => {
				timed_out = true;
				open_cancellable.cancel ();
				return Source.REMOVE;
			});
			timeout_source.attach (main_context);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				open_cancellable.cancel ();
				return Source.REMOVE;
			});
			cancel_source.attach (main_context);

			try {
				return yield open_tcp_connection (address, open_cancellable);
			} catch (IOError e) {
				assert (e is IOError.CANCELLED);
				if (timed_out)
					throw new Efni.Error.TIMED_OUT ("Networked Apple device is not responding");
				throw e;
			} finally {
				timeout_source.destroy ();
				cancel_source.destroy ();
			}
		}

		public abstract UdpSocket create_udp_socket () throws Efni.Error;
	}

	public interface UdpSocket : Object {
		public abstract DatagramBased datagram_based {
			get;
		}

		public abstract void bind (InetSocketAddress address) throws Efni.Error;
		public abstract InetSocketAddress get_local_address () throws Efni.Error;
		public abstract void socket_connect (InetSocketAddress address, Cancellable? cancellable) throws Efni.Error;
	}

	public sealed class SystemNetworkStack : Object, NetworkStack {
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

		public SystemNetworkStack (InetAddress listener_ip, uint scope_id) {
			_listener_ip = listener_ip;
			_scope_id = scope_id;
		}

		public async IOStream open_tcp_connection (InetSocketAddress address, Cancellable? cancellable) throws Efni.Error, IOError {
			SocketConnection connection;
			try {
				var client = new SocketClient ();
				connection = yield client.connect_async (address, cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CONNECTION_REFUSED)
					throw new Efni.Error.SERVER_NOT_RUNNING ("%s", e.message);
				throw new Efni.Error.TRANSPORT ("%s", e.message);
			}

			Tcp.enable_nodelay (connection.socket);

			return connection;
		}

		public UdpSocket create_udp_socket () throws Efni.Error {
			try {
				var handle = new Socket (IPV6, DATAGRAM, UDP);
				return new SystemUdpSocket (handle);
			} catch (GLib.Error e) {
				throw new Efni.Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		private class SystemUdpSocket : Object, UdpSocket {
			public Socket handle {
				get;
				construct;
			}

			public DatagramBased datagram_based {
				get {
					return handle;
				}
			}

			public SystemUdpSocket (Socket handle) {
				Object (handle: handle);
			}

			public void bind (InetSocketAddress address) throws Efni.Error {
				try {
					handle.bind (address, true);
				} catch (GLib.Error e) {
					throw new Efni.Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			public InetSocketAddress get_local_address () throws Efni.Error {
				try {
					return (InetSocketAddress) handle.get_local_address ();
				} catch (GLib.Error e) {
					throw new Efni.Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			public void socket_connect (InetSocketAddress address, Cancellable? cancellable) throws Efni.Error {
				try {
					handle.connect (address, cancellable);
				} catch (GLib.Error e) {
					throw new Efni.Error.TRANSPORT ("%s", e.message);
				}
			}
		}
	}
}
