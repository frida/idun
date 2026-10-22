using Efni;

namespace Idun {
	public sealed class DTXConnection : Object, DTXTransport {
		public IOStream stream {
			get;
			construct;
		}

		public State state {
			get {
				return _state;
			}
		}

		public enum State {
			OPEN,
			CLOSED
		}

		private static Gee.HashMap<ChannelProvider, Future<DTXConnection>> connections;

		private State _state = OPEN;

		private DataInputStream input;
		private OutputStream output;
		private Cancellable io_cancellable = new Cancellable ();

		private Gee.HashMap<uint32, Gee.ArrayList<Fragment>> fragments = new Gee.HashMap<uint32, Gee.ArrayList<Fragment>> ();
		private uint32 next_fragment_identifier = 1;
		private Gee.ArrayQueue<Bytes> pending_writes = new Gee.ArrayQueue<Bytes> ();

		private DTXControlChannel control_channel;
		private Gee.HashMap<uint32, unowned DTXChannel> channels = new Gee.HashMap<uint32, unowned DTXChannel> ();
		private int32 next_channel_code = 1;

		private const uint32 DTX_FRAGMENT_MAGIC = 0x1f3d5b79U;
		private const size_t MAX_MESSAGE_SIZE = 128 * 1024 * 1024;
		private const size_t MAX_FRAGMENT_SIZE = 128 * 1024;
		private const string REMOTESERVER_ENDPOINT_17PLUS = "lockdown:com.apple.instruments.dtservicehub";
		private const string REMOTESERVER_ENDPOINT_14PLUS = "lockdown:com.apple.instruments.remoteserver.DVTSecureSocketProxy";
		private const string REMOTESERVER_ENDPOINT_LEGACY = "lockdown:com.apple.instruments.remoteserver?tls=handshake-only";
 		private const string[] REMOTESERVER_ENDPOINT_CANDIDATES = {
			REMOTESERVER_ENDPOINT_17PLUS,
			REMOTESERVER_ENDPOINT_14PLUS,
			REMOTESERVER_ENDPOINT_LEGACY,
		};

		public static async DTXConnection obtain (ChannelProvider channel_provider, Cancellable? cancellable)
				throws Efni.Error, IOError {
			if (connections == null)
				connections = new Gee.HashMap<ChannelProvider, Future<DTXConnection>> ();

			while (connections.has_key (channel_provider)) {
				var future = connections[channel_provider];
				try {
					return yield future.wait_async (cancellable);
				} catch (Efni.Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}

			var request = new Promise<DTXConnection> ();
			connections[channel_provider] = request.future;

			Efni.Error pending_error = null;

			foreach (unowned string endpoint in REMOTESERVER_ENDPOINT_CANDIDATES) {
				try {
					var stream = yield channel_provider.open_channel (endpoint, cancellable);

					var connection = new DTXConnection (stream);
					connection.notify["state"].connect (on_connection_state_changed);

					request.resolve (connection);

					return connection;
				} catch (Efni.Error e) {
					if (!(e is Efni.Error.NOT_SUPPORTED)) {
						pending_error = e;
						break;
					}
				}
			}

			Efni.Error api_error = (pending_error == null)
				? new Efni.Error.NOT_SUPPORTED ("This feature requires an iOS Developer Disk Image to be mounted; " +
					"run Xcode briefly or use ideviceimagemounter to mount one manually")
				: pending_error;

			request.reject (api_error);
			connections.unset (channel_provider);

			throw api_error;
		}

		public static async void close_all (ChannelProvider channel_provider, Cancellable? cancellable) throws IOError {
			if (connections == null)
				return;

			while (connections.has_key (channel_provider)) {
				var future = connections[channel_provider];
				try {
					var connection = yield future.wait_async (cancellable);
					connections.unset (channel_provider);
					yield connection.close (cancellable);
				} catch (Efni.Error e) {
					continue;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}

			if (connections.size == 0)
				connections = null;
		}

		private static void on_connection_state_changed (Object object, ParamSpec pspec) {
			DTXConnection connection = (DTXConnection) object;
			if (connection.state != CLOSED)
				return;

			foreach (var entry in connections.entries) {
				var future = entry.value;

				if (future.ready) {
					DTXConnection c = future.value;
					if (c == connection) {
						connections.unset (entry.key);
						return;
					}
				}
			}
		}

		public DTXConnection (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			input = new DataInputStream (stream.get_input_stream ());
			input.byte_order = LITTLE_ENDIAN;
			output = stream.get_output_stream ();

			control_channel = new DTXControlChannel (this);
			channels[control_channel.code] = control_channel;

			try {
				control_channel.notify_of_published_capabilities ();
			} catch (Efni.Error e) {
				assert_not_reached ();
			}

			process_incoming_fragments.begin ();
		}

		public override void dispose () {
			foreach (var channel in channels.values)
				channel.transport = null;
			channels.clear ();

			base.dispose ();
		}

		private async void close (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();

			var source = new IdleSource ();
			source.set_callback (close.callback);
			source.attach (MainContext.get_thread_default ());
			yield;

			try {
				yield stream.close_async (Priority.DEFAULT, cancellable);
			} catch (IOError e) {
			}
		}

		public DTXChannel make_channel (string identifier) throws Efni.Error {
			check_open ();

			int32 channel_code = next_channel_code++;

			var channel = new DTXChannel (channel_code, this);
			channels[channel_code] = channel;

			establish_channel.begin (channel, identifier);

			return channel;
		}

		private void remove_channel (DTXChannel channel) {
			channels.unset (channel.code);

			if (channel != control_channel)
				control_channel.cancel_channel.begin (channel.code, io_cancellable);
		}

		private async void establish_channel (DTXChannel channel, string identifier) {
			try {
				yield control_channel.request_channel (channel.code, identifier, io_cancellable);
			} catch (GLib.Error e) {
				channels.unset (channel.code);
			}
		}

		private async void process_incoming_fragments () {
			while (true) {
				try {
					var fragment = yield read_fragment ();

					if (fragment.count == 1) {
						process_message (fragment.bytes.get_data (), fragment);
						continue;
					}

					Gee.ArrayList<Fragment> entries = fragments[fragment.identifier];
					if (entries == null) {
						if (fragment.index != 0)
							throw new Efni.Error.PROTOCOL ("Expected first fragment to have index of zero");
						fragment.data_size = 0;

						entries = new Gee.ArrayList<Fragment> ();
						fragments[fragment.identifier] = entries;
					}
					entries.add (fragment);

					var first_fragment = entries[0];

					if (fragment.bytes != null) {
						var size = fragment.bytes.get_size ();

						first_fragment.data_size += (uint32) size;
						if (first_fragment.data_size > MAX_MESSAGE_SIZE)
							throw new Efni.Error.PROTOCOL ("Message size exceeds maximum");
					}

					if (entries.size == fragment.count) {
						var message = new uint8[first_fragment.data_size];

						var sorted_entries = entries.order_by ((a, b) => (int) a.index - (int) b.index);
						uint i = 0;
						size_t offset = 0;
						while (sorted_entries.next ()) {
							Fragment f = sorted_entries.get ();

							if (f.index != i)
								throw new Efni.Error.PROTOCOL ("Inconsistent fragments received");

							var bytes = f.bytes;
							if (bytes != null) {
								var size = bytes.get_size ();
								Memory.copy ((uint8 *) message + offset, (uint8 *) bytes.get_data (), size);
								offset += size;
							}

							i++;
						}

						fragments.unset (fragment.identifier);

						process_message (message, first_fragment);
					}
				} catch (GLib.Error e) {
					_state = CLOSED;
					notify_property ("state");

					foreach (var channel in channels.values.to_array ())
						channel.close ();
					channels.clear ();

					return;
				}
			}
		}

		private async Fragment read_fragment () throws Efni.Error, IOError {
			var io_priority = Priority.DEFAULT;

			try {
				size_t minimum_header_size = 32;

				yield prepare_to_read (minimum_header_size);

				uint32 magic = input.read_uint32 (io_cancellable);
				if (magic != DTX_FRAGMENT_MAGIC)
					throw new Efni.Error.PROTOCOL ("Expected DTX message magic, got 0x%08x", magic);

				var fragment = new Fragment ();

				var header_size = input.read_uint32 (io_cancellable);
				if (header_size < minimum_header_size)
					throw new Efni.Error.PROTOCOL ("Expected header size of >= 32, got %u", header_size);

				fragment.index = input.read_uint16 (io_cancellable);
				fragment.count = input.read_uint16 (io_cancellable);
				fragment.data_size = input.read_uint32 (io_cancellable);
				fragment.identifier = input.read_uint32 (io_cancellable);
				fragment.conversation_index = input.read_uint32 (io_cancellable);
				fragment.channel_code = input.read_int32 (io_cancellable);
				fragment.flags = input.read_uint32 (io_cancellable);

				size_t extra_header_size = header_size - minimum_header_size;
				if (extra_header_size > 0)
					yield input.skip_async (extra_header_size, io_priority, io_cancellable);

				if (fragment.count == 1 || fragment.index != 0) {
					if (fragment.data_size == 0)
						throw new Efni.Error.PROTOCOL ("Empty fragments are not allowed");
					if (fragment.data_size > MAX_FRAGMENT_SIZE)
						throw new Efni.Error.PROTOCOL ("Fragment size exceeds maximum");

					if (fragment.data_size > input.get_buffer_size ())
						input.set_buffer_size (fragment.data_size);

					yield prepare_to_read (fragment.data_size);
					fragment.bytes = input.read_bytes (fragment.data_size, io_cancellable);
				}

				return fragment;
			} catch (GLib.Error e) {
				if (e is Efni.Error)
					throw (Efni.Error) e;
				throw new Efni.Error.TRANSPORT ("%s", e.message);
			}
		}

		private void process_message (uint8[] raw_message, Fragment fragment) throws Efni.Error {
			const size_t header_size = 16;

			size_t message_size = raw_message.length;
			if (message_size < header_size)
				throw new Efni.Error.PROTOCOL ("Malformed message");

			uint8 * m = (uint8 *) raw_message;

			var message = DTXMessage ();
			message.type = (DTXMessageType) *m;
			message.identifier = fragment.identifier;
			message.conversation_index = fragment.conversation_index;
			message.channel_code = fragment.channel_code;
			message.transport_flags = (DTXMessageTransportFlags) fragment.flags;

			uint32 aux_size = uint32.from_little_endian (*((uint32 *) (m + 4)));
			uint64 data_size = uint64.from_little_endian (*((uint64 *) (m + 8)));
			if (aux_size > message_size || data_size > message_size || data_size != message_size - header_size ||
					aux_size > data_size) {
				throw new Efni.Error.PROTOCOL ("Malformed message");
			}

			size_t aux_start_offset = header_size;
			size_t aux_end_offset = aux_start_offset + aux_size;
			message.aux_data = raw_message[aux_start_offset:aux_end_offset];

			size_t payload_start_offset = aux_end_offset;
			size_t payload_end_offset = payload_start_offset + (size_t) (data_size - aux_size);
			message.payload_data = raw_message[payload_start_offset:payload_end_offset];

			int32 channel_code = message.channel_code;
			if ((message.conversation_index % 2) == 0)
				channel_code = -channel_code;

			bool is_notification = message.conversation_index == 0;

			var channel = channels[channel_code];
			if (channel == null)
				return;

			switch (message.type) {
				case DISPATCH:
					channel.handle_dispatch (message);
					break;
				case OK:
				case OBJECT:
				case ERROR:
					if (is_notification)
						channel.handle_notification (message);
					else
						channel.handle_response (message);
					break;
				case DATA:
					channel.handle_data (message);
					break;
				case BARRIER:
					channel.handle_barrier (message);
					break;
				case PRIMITIVE:
				case COMPRESSED:
				case PROXIED_MESSAGE:
					throw new Efni.Error.PROTOCOL ("Unsupported message type: %s", message.type.to_string ());
			}
		}

		private void send_message (DTXMessage message, out uint32 identifier) {
			const size_t message_header_size = 16;
			uint32 message_aux_size = message.aux_data.length;
			uint64 message_data_size = message_aux_size + message.payload_data.length;
			size_t message_size = message_header_size + (size_t) message_data_size;
			const uint8 message_flags_a = 0;
			const uint8 message_flags_b = 0;
			const uint8 message_reserved = 0;

			const uint32 fragment_header_size = 32;
			const uint16 fragment_index = 0;
			const uint16 fragment_count = 1;
			uint32 fragment_data_size = (uint32) message_size;
			uint32 fragment_identifier = message.identifier;
			if (fragment_identifier == 0)
				fragment_identifier = next_fragment_identifier++;
			uint32 fragment_flags = message.transport_flags;

			var data = new uint8[fragment_header_size + message_size];

			uint8 * p = (uint8 *) data;
			*((uint32 *) (p + 0)) = DTX_FRAGMENT_MAGIC.to_little_endian ();
			*((uint32 *) (p + 4)) = fragment_header_size.to_little_endian ();
			*((uint16 *) (p + 8)) = fragment_index.to_little_endian ();
			*((uint16 *) (p + 10)) = fragment_count.to_little_endian ();
			*((uint32 *) (p + 12)) = fragment_data_size.to_little_endian ();
			*((uint32 *) (p + 16)) = fragment_identifier.to_little_endian ();
			*((uint32 *) (p + 20)) = message.conversation_index.to_little_endian ();
			*((int32 *) (p + 24)) = message.channel_code.to_little_endian ();
			*((uint32 *) (p + 28)) = fragment_flags.to_little_endian ();
			p += fragment_header_size;

			*(p + 0) = message.type;
			*(p + 1) = message_flags_a;
			*(p + 2) = message_flags_b;
			*(p + 3) = message_reserved;
			*((uint32 *) (p + 4)) = message_aux_size.to_little_endian ();
			*((uint64 *) (p + 8)) = message_data_size.to_little_endian ();
			p += message_header_size;

			Memory.copy (p, message.aux_data, message.aux_data.length);
			p += message.aux_data.length;

			Memory.copy (p, message.payload_data, message.payload_data.length);
			p += message.payload_data.length;

			assert (p == (uint8 *) data + data.length);

			write_bytes (new Bytes.take ((owned) data));

			identifier = fragment_identifier;
		}

		private async void prepare_to_read (size_t required) throws GLib.Error {
			while (true) {
				size_t available = input.get_available ();
				if (available >= required)
					return;
				ssize_t n = yield input.fill_async ((ssize_t) (required - available), Priority.DEFAULT, io_cancellable);
				if (n == 0)
					throw new Efni.Error.TRANSPORT ("Connection closed");
			}
		}

		private void write_bytes (Bytes bytes) {
			pending_writes.offer_tail (bytes);
			if (pending_writes.size == 1)
				process_pending_writes.begin ();
		}

		private async void process_pending_writes () {
			while (!pending_writes.is_empty) {
				Bytes current = pending_writes.peek_head ();

				size_t bytes_written;
				try {
					yield output.write_all_async (current.get_data (), Priority.DEFAULT, io_cancellable,
						out bytes_written);
				} catch (GLib.Error e) {
					return;
				}

				pending_writes.poll_head ();
			}
		}

		private void check_open () throws Efni.Error {
			if (_state != OPEN)
				throw new Efni.Error.INVALID_OPERATION ("Connection is closed");
		}

		private class Fragment {
			public uint16 index;
			public uint16 count;
			public uint32 data_size;
			public uint32 identifier;
			public uint32 conversation_index;
			public int32 channel_code;
			public uint32 flags;
			public Bytes? bytes;
		}
	}

	private sealed class DTXControlChannel : DTXChannel {
		public DTXControlChannel (DTXTransport transport) {
			Object (code: 0, transport: transport);
		}

		public void notify_of_published_capabilities () throws Efni.Error {
			var capabilities = new NSDictionary ();
			capabilities.set_value ("com.apple.private.DTXConnection", new NSNumber.from_integer (1));
			capabilities.set_value ("com.apple.instruments.client.processcontrol.capability.terminationCallback",
				new NSNumber.from_integer (1));

			var args = new DTXArgumentListBuilder ()
				.append_object (capabilities);
			invoke_without_reply ("_notifyOfPublishedCapabilities:", args);
		}

		public async void request_channel (int32 code, string identifier, Cancellable? cancellable) throws Efni.Error, IOError {
			var args = new DTXArgumentListBuilder ()
				.append_int32 (code)
				.append_object (new NSString (identifier));
			yield invoke ("_requestChannelWithCode:identifier:", args, cancellable);
		}

		public async void cancel_channel (int32 code, Cancellable? cancellable) throws Efni.Error, IOError {
			var args = new DTXArgumentListBuilder ()
				.append_int32 (code);
			yield invoke ("_channelCanceled:", args, cancellable);
		}
	}

	public class DTXChannel : Object {
		public signal void invocation (string method_name, DTXArgumentList args, DTXMessageTransportFlags transport_flags);
		public signal void notification (NSObject obj);
		public signal void data (Bytes blob);
		public signal void barrier ();

		public int32 code {
			get;
			construct;
		}

		public weak DTXTransport? transport {
			get;
			set;
		}

		public State state {
			get {
				return _state;
			}
		}

		public enum State {
			OPEN,
			CLOSED
		}

		private State _state = OPEN;

		private Gee.HashMap<uint32, Promise<NSObject?>> pending_responses = new Gee.HashMap<uint32, Promise<NSObject?>> ();

		public DTXChannel (int32 code, DTXTransport transport) {
			Object (code: code, transport: transport);
		}

		public override void dispose () {
			close ();

			base.dispose ();
		}

		internal void close () {
			_state = CLOSED;
			notify_property ("state");

			var error = new Efni.Error.TRANSPORT ("Channel closed");
			foreach (var request in pending_responses.values.to_array ())
				request.reject (error);

			if (transport != null) {
				transport.remove_channel (this);
				transport = null;
			}
		}

		public async NSObject? invoke (string method_name, DTXArgumentListBuilder? args, Cancellable? cancellable)
				throws Efni.Error, IOError {
			check_open ();

			var message = DTXMessage ();
			message.type = DISPATCH;
			message.channel_code = code;
			message.transport_flags = EXPECTS_REPLY;

			Bytes aux_data;
			if (args != null) {
				aux_data = args.build ();
				message.aux_data = aux_data.get_data ();
			}

			var payload_data = NSKeyedArchive.encode (new NSString (method_name));
			message.payload_data = payload_data;

			uint32 identifier;
			transport.send_message (message, out identifier);

			var request = new Promise<NSObject?> ();
			pending_responses[identifier] = request;

			try {
				return yield request.future.wait_async (cancellable);
			} finally {
				pending_responses.unset (identifier);
			}
		}

		public void invoke_without_reply (string method_name, DTXArgumentListBuilder? args) throws Efni.Error {
			check_open ();

			var message = DTXMessage ();
			message.type = DISPATCH;
			message.channel_code = code;
			message.transport_flags = NONE;

			Bytes aux_data;
			if (args != null) {
				aux_data = args.build ();
				message.aux_data = aux_data.get_data ();
			}

			var payload_data = NSKeyedArchive.encode (new NSString (method_name));
			message.payload_data = payload_data;

			uint32 identifier;
			transport.send_message (message, out identifier);
		}

		internal void handle_dispatch (DTXMessage message) throws Efni.Error {
			NSString? method_name = NSKeyedArchive.decode (message.payload_data) as NSString;
			if (method_name == null)
				throw new Efni.Error.PROTOCOL ("Malformed dispatch payload");

			var args = DTXArgumentList.parse (message.aux_data);

			invocation (method_name.str, args, message.transport_flags);
		}

		internal void handle_response (DTXMessage message) throws Efni.Error {
			var request = pending_responses[message.identifier];
			if (request != null) {
				switch (message.type) {
					case OK:
						request.resolve (null);
						break;
					case OBJECT:
						request.resolve (NSKeyedArchive.decode (message.payload_data));
						break;
					case ERROR: {
						NSError? error = NSKeyedArchive.decode (message.payload_data) as NSError;
						if (error == null)
							throw new Efni.Error.PROTOCOL ("Malformed error payload");

						var description = new StringBuilder.sized (128);

						var user_info = error.user_info;
						if (user_info != null) {
							NSString? val;
							if (user_info.get_optional_value ("NSLocalizedDescription", out val))
								description.append (val.str);
						}

						if (description.len == 0) {
							description.append_printf ("Invocation failed; domain=%s code=%" +
									int64.FORMAT_MODIFIER + "d",
								error.domain.str, error.code);
						}

						request.reject (new Efni.Error.NOT_SUPPORTED ("%s", description.str));

						break;
					}
					default:
						assert_not_reached ();
				}
			}
		}

		internal void handle_notification (DTXMessage message) throws Efni.Error {
			var payload = NSKeyedArchive.decode (message.payload_data);
			notification (payload);
		}

		internal void handle_data (DTXMessage message) throws Efni.Error {
			data (new Bytes (message.payload_data));
		}

		internal void handle_barrier (DTXMessage message) throws Efni.Error {
			barrier ();
		}

		private void check_open () throws Efni.Error {
			if (_state != OPEN)
				throw new Efni.Error.INVALID_OPERATION ("Channel is closed");
		}
	}

	public interface DTXTransport : Object {
		public abstract void send_message (DTXMessage message, out uint32 identifier);
		public abstract void remove_channel (DTXChannel channel);
	}
}
