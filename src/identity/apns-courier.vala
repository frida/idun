using Efni;

namespace Idun {
	/**
	 * A live connection to Apple's push courier. Idun presents its activated push
	 * identity as the TLS client certificate and signs the courier's connect
	 * challenge with the push key, exactly as a real device's push daemon does,
	 * speaking the courier's packed (apns-pack-v1) protocol. A successful connect
	 * yields the device push token the identity services register against.
	 */
	public sealed class ApnsCourier : Object {
		public ApnsIdentity identity {
			get;
			construct;
		}

		public string host {
			get;
			construct;
		}

		public uint16 port {
			get;
			construct;
		}

		public Bytes? push_token {
			get;
			private set;
		}

		private TlsCertificate client_certificate;
		private IOStream connection;
		private InputStream input;
		private OutputStream output;

		private const uint8 COMMAND_CONNECT = 0x07;
		private const uint8 COMMAND_CONNECT_ACK = 0x08;
		private const uint8 COMMAND_NOTIFICATION = 0x0a;
		private const uint8 COMMAND_FILTER = 0x09;
		private const uint8 COMMAND_KEEP_ALIVE = 0x0c;
		private const uint8 COMMAND_KEEP_ALIVE_ACK = 0x0d;

		private const uint8 ITEM_RESPONSE = 0x01;
		private const uint8 ITEM_STATE = 0x02;
		private const uint8 ITEM_TOKEN = 0x03;
		private const uint8 ITEM_FLAGS = 0x05;
		private const uint8 ITEM_CERTIFICATE = 0x0c;
		private const uint8 ITEM_NONCE = 0x0d;
		private const uint8 ITEM_SIGNATURE = 0x0e;

		private const uint8 FILTER_ITEM_TOKEN = 0x01;
		private const uint8 FILTER_ITEM_TOPIC = 0x02;

		private const uint8 NOTIFICATION_ITEM_TOPIC = 0x01;
		private const uint8 NOTIFICATION_ITEM_TARGET = 0x02;
		private const uint8 NOTIFICATION_ITEM_PAYLOAD = 0x03;
		private const uint8 NOTIFICATION_ITEM_MESSAGE_ID = 0x04;

		public ApnsCourier (ApnsIdentity identity, string? host = null, uint16 port = 5223) {
			Object (
				identity: identity,
				host: host ?? "%u-courier.push.apple.com".printf (Random.int_range (1, 51)),
				port: port
			);
		}

		public async void open (Cancellable? cancellable = null) throws Efni.Error, IOError {
			yield establish_tls (cancellable);

			yield write_message (COMMAND_CONNECT, build_connect_payload (), cancellable);

			CourierMessage ack = yield read_message (cancellable);
			if (ack.command != COMMAND_CONNECT_ACK)
				throw new Efni.Error.PROTOCOL ("Expected a connect acknowledgement, got command 0x%02x", ack.command);
			if (!ack.integers.has_key (ITEM_RESPONSE) || ack.integers[ITEM_RESPONSE] != 0)
				throw new Efni.Error.PROTOCOL ("Push courier rejected the connection: response %s",
					ack.integers.has_key (ITEM_RESPONSE) ? ack.integers[ITEM_RESPONSE].to_string () : "(none)");

			push_token = ack.blobs[ITEM_TOKEN];
		}

		public async void keep_alive (Cancellable? cancellable = null) throws Efni.Error, IOError {
			yield write_message (COMMAND_KEEP_ALIVE, new uint8[0], cancellable);

			CourierMessage ack = yield read_message (cancellable);
			if (ack.command != COMMAND_KEEP_ALIVE_ACK)
				throw new Efni.Error.PROTOCOL ("Expected a keep-alive acknowledgement, got command 0x%02x", ack.command);
		}

		public async void ping (Cancellable? cancellable = null) throws Efni.Error, IOError {
			yield write_message (COMMAND_KEEP_ALIVE, new uint8[0], cancellable);
		}

		public async void subscribe (string[] topics, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var payload = new ByteArray ();
			append_bytes_item (payload, FILTER_ITEM_TOKEN, push_token.get_data ());
			foreach (unowned string topic in topics)
				append_bytes_item (payload, FILTER_ITEM_TOPIC, topic_hash (topic));
			yield write_message (COMMAND_FILTER, payload.steal (), cancellable);
		}

		public async void post (string topic, Bytes target_token, Bytes payload, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			var message_id = new uint8[4];
			OpenSSL.Rng.generate (message_id);

			var body = new ByteArray ();
			append_bytes_item (body, NOTIFICATION_ITEM_TOPIC, topic_hash (topic));
			append_bytes_item (body, NOTIFICATION_ITEM_TARGET, target_token.get_data ());
			append_bytes_item (body, NOTIFICATION_ITEM_PAYLOAD, payload.get_data ());
			append_bytes_item (body, NOTIFICATION_ITEM_MESSAGE_ID, message_id);
			yield write_message (COMMAND_NOTIFICATION, body.steal (), cancellable);
		}

		public async CourierNotification receive (Cancellable? cancellable = null) throws Efni.Error, IOError {
			while (true) {
				CourierMessage message = yield read_message (cancellable);
				if (message.command == COMMAND_NOTIFICATION)
					return new CourierNotification (message.blobs);
			}
		}

		private async void establish_tls (Cancellable? cancellable) throws Efni.Error, IOError {
			client_certificate = make_client_certificate ();

			SocketConnection socket;
			TlsClientConnection tls;
			try {
				socket = yield new SocketClient ().connect_to_host_async (host, port, cancellable);
				tls = TlsClientConnection.new (socket, new NetworkAddress (host, port));
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to reach the push courier: %s", e.message);
			}
			tls.set_certificate (client_certificate);
			tls.set_advertised_protocols ({ "apns-pack-v1", "apns-pack-v1:4096:4096", "apns-security-v3", null });

			try {
				yield tls.handshake_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Push courier TLS handshake failed: %s", e.message);
			}

			connection = tls;
			input = tls.input_stream;
			output = tls.output_stream;
		}

		private uint8[] build_connect_payload () throws Efni.Error {
			uint8[] nonce = make_nonce ();

			var payload = new ByteArray ();
			append_int_item (payload, ITEM_STATE, 1);
			append_int_item (payload, ITEM_FLAGS, 0x8040);
			append_bytes_item (payload, ITEM_CERTIFICATE, client_certificate.certificate.data);
			append_bytes_item (payload, ITEM_NONCE, nonce);
			append_bytes_item (payload, ITEM_SIGNATURE, sign_nonce (nonce));
			append_int_item (payload, 0x10, 0x0c);
			append_int_item (payload, 0x11, 0);
			append_int_item (payload, 0x1a, 0);
			append_int_item (payload, 0x1f, 8);
			return payload.steal ();
		}

		private static uint8[] make_nonce () {
			var nonce = new uint8[17];
			nonce[0] = 0x00;
			int64 milliseconds = get_real_time () / 1000;
			for (uint i = 0; i != 8; i++)
				nonce[1 + i] = (uint8) (milliseconds >> (int) (56 - 8 * i));
			for (uint i = 0; i != 8; i++)
				nonce[9 + i] = (uint8) Random.int_range (0, 256);
			return nonce;
		}

		private uint8[] sign_nonce (uint8[] nonce) throws Efni.Error {
			var source = new OpenSSL.BasicIO.from_static_memory_buffer (identity.private_key.get_data ());
			OpenSSL.Envelope.Key? key = new OpenSSL.Envelope.Key.from_private_key_pem (source);
			if (key == null)
				throw new Efni.Error.PROTOCOL ("Unable to load the push private key");

			var ctx = new OpenSSL.Envelope.MessageDigestContext ();
			ctx.digest_sign_init (null, OpenSSL.Envelope.MessageDigest.fetch (null, "SHA1"), null, key);

			size_t length = 0;
			ctx.digest_sign (null, ref length, nonce);
			var raw = new uint8[length];
			ctx.digest_sign (raw, ref length, nonce);

			var signature = new uint8[2 + length];
			signature[0] = 0x01;
			signature[1] = 0x01;
			for (uint i = 0; i != length; i++)
				signature[2 + i] = raw[i];
			return signature;
		}

		private TlsCertificate make_client_certificate () throws Efni.Error {
			var pem = new ByteArray ();
			pem.append (identity.push_certificate.get_data ());
			pem.append ({ '\n' });
			pem.append (identity.private_key.get_data ());
			try {
				return new TlsCertificate.from_pem ((string) pem.data, (ssize_t) pem.len);
			} catch (GLib.Error e) {
				throw new Efni.Error.PROTOCOL ("Unable to load the push identity: %s", e.message);
			}
		}

		private async void write_message (uint8 command, uint8[] payload, Cancellable? cancellable)
				throws Efni.Error, IOError {
			var frame = new ByteArray ();
			frame.append ({ command });
			append_varint (frame, payload.length, 8);
			frame.append (payload);

			try {
				yield output.write_all_async (frame.data, Priority.DEFAULT, cancellable, null);
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to write to the push courier: %s", e.message);
			}
		}

		private async CourierMessage read_message (Cancellable? cancellable) throws Efni.Error, IOError {
			uint8 command = yield read_byte (cancellable);
			uint64 length = yield read_varint (8, cancellable);

			var payload = new uint8[length];
			yield read_exact (payload, cancellable);

			return new CourierMessage (command, payload);
		}

		private async uint8 read_byte (Cancellable? cancellable) throws Efni.Error, IOError {
			var one = new uint8[1];
			yield read_exact (one, cancellable);
			return one[0];
		}

		private async uint64 read_varint (uint prefix_bits, Cancellable? cancellable) throws Efni.Error, IOError {
			uint64 cap = ((uint64) 1 << prefix_bits) - 1;
			uint64 first = yield read_byte (cancellable);
			if (first < cap)
				return first;

			uint64 value = cap;
			uint shift = 0;
			while (true) {
				uint8 b = yield read_byte (cancellable);
				value += (uint64) (b & 0x7f) << shift;
				shift += 7;
				if ((b & 0x80) == 0)
					break;
			}
			return value;
		}

		private async void read_exact (uint8[] buffer, Cancellable? cancellable) throws Efni.Error, IOError {
			size_t read = 0;
			try {
				if (!yield input.read_all_async (buffer, Priority.DEFAULT, cancellable, out read))
					throw new Efni.Error.TRANSPORT ("Push courier closed the connection");
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to read from the push courier: %s", e.message);
			}
		}

		private static uint8[] topic_hash (string topic) {
			var checksum = new Checksum (ChecksumType.SHA1);
			checksum.update (topic.data, topic.data.length);
			var digest = new uint8[20];
			size_t length = digest.length;
			checksum.get_digest (digest, ref length);
			return digest;
		}

		private static void append_int_item (ByteArray buffer, uint8 id, uint64 value) {
			append_item_id (buffer, id);
			if (value <= 31) {
				buffer.append ({ (uint8) (0x80 | value) });
			} else {
				uint count = byte_count (value);
				buffer.append ({ (uint8) (0xa0 | (count - 1)) });
				for (int i = (int) count - 1; i >= 0; i--)
					buffer.append ({ (uint8) (value >> (8 * i)) });
			}
		}

		private static void append_bytes_item (ByteArray buffer, uint8 id, uint8[] data) {
			append_item_id (buffer, id);
			append_varint (buffer, data.length, 6);
			buffer.append (data);
		}

		private static void append_item_id (ByteArray buffer, uint8 id) {
			if (id >= 0x10)
				buffer.append ({ 0x10 });
			buffer.append ({ id });
		}

		private static void append_varint (ByteArray buffer, uint64 value, uint prefix_bits) {
			uint64 cap = ((uint64) 1 << prefix_bits) - 1;
			if (value < cap) {
				buffer.append ({ (uint8) value });
				return;
			}
			buffer.append ({ (uint8) cap });
			value -= cap;
			while (value >= 128) {
				buffer.append ({ (uint8) ((value & 0x7f) | 0x80) });
				value >>= 7;
			}
			buffer.append ({ (uint8) value });
		}

		private static uint byte_count (uint64 value) {
			uint count = 1;
			while ((value >>= 8) != 0)
				count++;
			return count;
		}
	}

	public sealed class CourierNotification : Object {
		public Bytes? topic {
			get;
			construct;
		}

		public Bytes? token {
			get;
			construct;
		}

		public Bytes? payload {
			get;
			construct;
		}

		internal CourierNotification (Gee.Map<uint8, Bytes> blobs) {
			Object (
				topic: blobs.has_key (0x01) ? blobs[0x01] : null,
				token: blobs.has_key (0x02) ? blobs[0x02] : null,
				payload: blobs.has_key (0x03) ? blobs[0x03] : null
			);
		}
	}

	private sealed class CourierMessage : Object {
		public uint8 command {
			get;
			construct;
		}

		public Gee.Map<uint8, uint64?> integers {
			get;
			construct;
		}

		public Gee.Map<uint8, Bytes> blobs {
			get;
			construct;
		}

		public CourierMessage (uint8 command, uint8[] payload) {
			var integers = new Gee.HashMap<uint8, uint64?> ();
			var blobs = new Gee.HashMap<uint8, Bytes> ();

			uint pos = 0;
			while (pos < payload.length) {
				uint8 repr = payload[pos];
				uint8 id;
				if (repr <= 0x0f) {
					id = repr;
					pos += 1;
				} else if (repr == 0x10) {
					if (pos + 1 >= payload.length)
						break;
					id = payload[pos + 1];
					pos += 2;
				} else if (repr >= 0x40 && repr <= 0x7f) {
					id = repr & 0x3f;
					pos += 1;
				} else {
					break;
				}

				if (pos >= payload.length)
					break;
				uint8 tag = payload[pos];
				if (tag <= 0x7f) {
					uint64 length = read_varint (payload, ref pos, 6);
					if (pos + length > payload.length)
						break;
					blobs[id] = new Bytes (payload[pos:pos + length]);
					pos += (uint) length;
				} else if (tag >= 0x80 && tag <= 0x9f) {
					integers[id] = tag & 0x1f;
					pos += 1;
				} else if (tag >= 0xa0 && tag <= 0xbf) {
					uint count = (tag & 0x1f) + 1;
					pos += 1;
					if (pos + count > payload.length)
						break;
					uint64 value = 0;
					for (uint i = 0; i != count; i++)
						value = (value << 8) | payload[pos + i];
					pos += count;
					integers[id] = value;
				} else {
					break;
				}
			}

			Object (command: command, integers: integers, blobs: blobs);
		}

		private static uint64 read_varint (uint8[] buffer, ref uint pos, uint prefix_bits) {
			uint64 cap = ((uint64) 1 << prefix_bits) - 1;
			uint64 first = buffer[pos] & cap;
			pos += 1;
			if (first < cap)
				return first;

			uint64 value = cap;
			uint shift = 0;
			while (pos < buffer.length) {
				uint8 b = buffer[pos];
				pos += 1;
				value += (uint64) (b & 0x7f) << shift;
				shift += 7;
				if ((b & 0x80) == 0)
					break;
			}
			return value;
		}
	}
}
