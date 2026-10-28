using Efni;

namespace Idun {
	/**
	 * The QUIC link a device holds to a FaceTime QuickRelay. Its TLS handshake carries no
	 * certificate; the relay authenticates the device by the external pre-shared key the
	 * allocation's session key derives, and the HTTP/3 control messages that join the call
	 * and exchange its media keys ride this one connection once it is up.
	 */
	public sealed class FaceTimeRelayConnection : Object, AsyncInitable {
		public InetSocketAddress address {
			get;
			construct;
		}

		public Bytes psk_identity {
			get;
			construct;
		}

		public Bytes psk_key {
			get;
			construct;
		}

		private Promise<bool> establish_request = new Promise<bool> ();

		private Socket? socket;
		private uint8[] raw_local_address;
		private NGTcp2.Connection? connection;
		private NGTcp2.Crypto.ConnectionRef connection_ref;
		private OpenSSL.SSLContext ssl_ctx;
		private OpenSSL.SSL ssl;
#if HAVE_NGTCP2_CRYPTO_OSSL
		private NGTcp2.Crypto.Ossl.Context ossl_ctx;
#endif

		private Source? rx_source;
		private int tx_count;
		private int rx_count;
		private bool psk_invoked;
		private uint8[] rx_buf = new uint8[MAX_UDP_PAYLOAD_SIZE];
		private uint8[] tx_buf = new uint8[MAX_UDP_PAYLOAD_SIZE];
		private Source? write_idle;
		private Source? expiry_timer;
		private MainContext main_context;
		private Cancellable io_cancellable = new Cancellable ();

		private const string ALPN = "\x02h3";
		private const size_t MAX_UDP_PAYLOAD_SIZE = 1452;
		private const uint8[] TLS_AES_128_GCM_SHA256 = { 0x13, 0x01 };

		public static async FaceTimeRelayConnection open (InetSocketAddress address,
				Bytes psk_identity, Bytes psk_key, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var connection = new FaceTimeRelayConnection (address, psk_identity, psk_key);
			try {
				yield connection.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}
			return connection;
		}

		private FaceTimeRelayConnection (InetSocketAddress address, Bytes psk_identity, Bytes psk_key) {
			Object (address: address, psk_identity: psk_identity, psk_key: psk_key);
		}

		construct {
			connection_ref.get_conn = conn_ref => {
				FaceTimeRelayConnection * self = conn_ref.user_data;
				return self->connection;
			};
			connection_ref.user_data = this;

			ssl_ctx = new OpenSSL.SSLContext (OpenSSL.SSLMethod.tls_client ());
#if !HAVE_NGTCP2_CRYPTO_OSSL
			NGTcp2.Crypto.Quictls.configure_client_context (ssl_ctx);
#endif

			ssl = new OpenSSL.SSL (ssl_ctx);
#if HAVE_NGTCP2_CRYPTO_OSSL
			NGTcp2.Crypto.Ossl.init ();
			NGTcp2.Crypto.Ossl.Context.create (out ossl_ctx, ssl);
			NGTcp2.Crypto.Ossl.configure_client_session (ssl);
#endif
			ssl.set_app_data (&connection_ref);
			ssl.set_connect_state ();
			ssl.set_alpn_protos (ALPN.data);
			ssl.set_psk_use_session_callback (on_psk_use_session);
#if !HAVE_NGTCP2_CRYPTO_OSSL
			ssl.set_quic_transport_version (OpenSSL.TLSExtensionType.quic_transport_parameters);
#endif

			main_context = MainContext.ref_thread_default ();
		}

		public override void dispose () {
			perform_teardown ();
			base.dispose ();
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Efni.Error, IOError {
			try {
				socket = new Socket (address.get_family (), DATAGRAM, UDP);
				socket.bind (new InetSocketAddress (new InetAddress.any (address.get_family ()), 0), true);
				socket.connect (address, cancellable);
			} catch (GLib.Error e) {
				throw new Efni.Error.TRANSPORT ("Unable to reach the QuickRelay: %s", e.message);
			}

			raw_local_address = address_to_native (socket.get_local_address ());
			uint8[] raw_remote_address = address_to_native (address);

			var path = NGTcp2.Path () {
				local = NGTcp2.Address () { addr = raw_local_address },
				remote = NGTcp2.Address () { addr = raw_remote_address },
			};

			var callbacks = NGTcp2.Callbacks () {
				client_initial = NGTcp2.Crypto.client_initial_cb,
				recv_crypto_data = NGTcp2.Crypto.recv_crypto_data_cb,
				handshake_completed = (conn, user_data) => {
					FaceTimeRelayConnection * self = user_data;
					return self->on_handshake_completed ();
				},
				encrypt = NGTcp2.Crypto.encrypt_cb,
				decrypt = NGTcp2.Crypto.decrypt_cb,
				hp_mask = NGTcp2.Crypto.hp_mask_cb,
				recv_retry = NGTcp2.Crypto.recv_retry_cb,
				rand = on_rand,
				get_new_connection_id = on_get_new_connection_id,
				update_key = NGTcp2.Crypto.update_key_cb,
				delete_crypto_aead_ctx = NGTcp2.Crypto.delete_crypto_aead_ctx_cb,
				delete_crypto_cipher_ctx = NGTcp2.Crypto.delete_crypto_cipher_ctx_cb,
				get_path_challenge_data = NGTcp2.Crypto.get_path_challenge_data_cb,
				version_negotiation = NGTcp2.Crypto.version_negotiation_cb,
			};

			var dcid = make_connection_id (NGTcp2.MIN_INITIAL_DCIDLEN);
			var scid = make_connection_id (NGTcp2.MIN_INITIAL_DCIDLEN);

			var settings = NGTcp2.Settings.make_default ();
			settings.initial_ts = make_timestamp ();
			settings.handshake_timeout = 10ULL * NGTcp2.SECONDS;

			var transport_params = NGTcp2.TransportParams.make_default ();
			transport_params.max_idle_timeout = 30ULL * NGTcp2.SECONDS;
			transport_params.initial_max_data = 1048576;
			transport_params.initial_max_stream_data_bidi_local = 1048576;
			transport_params.initial_max_stream_data_uni = 1048576;
			transport_params.initial_max_streams_uni = 3;

			NGTcp2.Connection.make_client (out connection, dcid, scid, path, NGTcp2.ProtocolVersion.V1, callbacks,
				settings, transport_params, null, this);
#if HAVE_NGTCP2_CRYPTO_OSSL
			connection.set_tls_native_handle (ossl_ctx);
#else
			connection.set_tls_native_handle (ssl);
#endif

			var source = socket.create_source (IOCondition.IN, io_cancellable);
			source.set_callback (on_socket_readable);
			source.attach (main_context);
			rx_source = source;

			process_pending_writes ();

			yield establish_request.future.wait_async (cancellable);
			return true;
		}

		private static int on_psk_use_session (OpenSSL.SSL ssl, OpenSSL.Envelope.MessageDigest? md,
				out uint8 * id, out size_t idlen, out OpenSSL.SSLSession? session) {
			NGTcp2.Crypto.ConnectionRef * conn_ref = ssl.get_app_data ();
			FaceTimeRelayConnection * self = conn_ref->user_data;
			self->psk_invoked = true;

			unowned OpenSSL.SSLCipher? cipher = ssl.find_cipher (TLS_AES_128_GCM_SHA256);
			if (cipher == null) {
				id = null;
				idlen = 0;
				session = null;
				return 0;
			}

			var created = new OpenSSL.SSLSession ();
			created.set_cipher (cipher);
			created.set_protocol_version (OpenSSL.TLS1_3_VERSION);
			created.set_master_key (self->psk_key.get_data ());

			id = self->psk_identity.get_data ();
			idlen = self->psk_identity.get_size ();
			session = (owned) created;
			return 1;
		}

		private int on_handshake_completed () {
			if (!establish_request.future.ready)
				establish_request.resolve (true);
			return 0;
		}

		private void perform_teardown () {
			if (establish_request.future.ready && connection == null)
				return;

			connection = null;
			ssl.set_app_data (null);
			socket = null;
			io_cancellable.cancel ();

			if (rx_source != null) {
				rx_source.destroy ();
				rx_source = null;
			}
			if (write_idle != null) {
				write_idle.destroy ();
				write_idle = null;
			}
			if (expiry_timer != null) {
				expiry_timer.destroy ();
				expiry_timer = null;
			}

			if (!establish_request.future.ready)
				establish_request.reject (new Efni.Error.TRANSPORT (
					"QuickRelay handshake not completed (tx=%d rx=%d psk=%s)",
					tx_count, rx_count, psk_invoked ? "yes" : "no"));
		}

		private bool on_socket_readable (Socket readable, IOCondition condition) {
			try {
				InetSocketAddress remote_address;
				size_t n = Udp.recv (rx_buf, socket, io_cancellable, out remote_address);
				rx_count++;

				var path = NGTcp2.Path () {
					local = NGTcp2.Address () { addr = raw_local_address },
					remote = NGTcp2.Address () { addr = address_to_native (remote_address) },
				};

				var res = connection.read_packet (path, null, rx_buf[:n], make_timestamp ());
				if (res == NGTcp2.ErrorCode.DRAINING)
					perform_teardown ();
			} catch (GLib.Error e) {
				return Source.REMOVE;
			} finally {
				process_pending_writes ();
			}
			return Source.CONTINUE;
		}

		private void process_pending_writes () {
			if (connection == null || write_idle != null)
				return;

			var source = new IdleSource ();
			source.set_callback (() => {
				write_idle = null;
				do_process_pending_writes ();
				return Source.REMOVE;
			});
			source.attach (main_context);
			write_idle = source;
		}

		private void do_process_pending_writes () {
			var ts = make_timestamp ();
			var pi = NGTcp2.PacketInfo ();

			while (true) {
				ssize_t datalen = 0;
				ssize_t n = connection.write_stream (null, &pi, tx_buf, &datalen, NGTcp2.WriteStreamFlags.NONE,
					-1, null, ts);
				if (n == 0)
					break;
				if (n == NGTcp2.ErrorCode.WRITE_MORE)
					continue;
				if (n == NGTcp2.ErrorCode.CLOSING) {
					perform_teardown ();
					break;
				}
				if (n < 0)
					break;

				try {
					Udp.send (tx_buf[:n], socket, io_cancellable);
					tx_count++;
				} catch (GLib.Error e) {
					break;
				}
			}

			schedule_expiry ();
		}

		private void schedule_expiry () {
			if (expiry_timer != null) {
				expiry_timer.destroy ();
				expiry_timer = null;
			}
			if (connection == null)
				return;

			NGTcp2.Timestamp expiry = connection.get_expiry ();
			if (expiry == uint64.MAX)
				return;

			NGTcp2.Timestamp now = make_timestamp ();
			uint delta_msec = (expiry > now) ? (uint) ((expiry - now) / 1000000ULL) : 1;

			var source = new TimeoutSource (delta_msec);
			source.set_callback (on_expiry);
			source.attach (main_context);
			expiry_timer = source;
		}

		private bool on_expiry () {
			if (connection.handle_expiry (make_timestamp ()) != 0) {
				perform_teardown ();
				return Source.REMOVE;
			}
			process_pending_writes ();
			return Source.REMOVE;
		}

		private static int on_get_new_connection_id (NGTcp2.Connection conn, out NGTcp2.ConnectionID cid,
				uint8[] token, size_t cidlen, void * user_data) {
			cid = make_connection_id (cidlen);
			OpenSSL.Rng.generate (token[:NGTcp2.STATELESS_RESET_TOKENLEN]);
			return 0;
		}

		private static void on_rand (uint8[] dest, NGTcp2.RNGContext rand_ctx) {
			OpenSSL.Rng.generate (dest);
		}

		private static uint8[] address_to_native (SocketAddress address) {
			var size = address.get_native_size ();
			var buf = new uint8[size];
			try {
				address.to_native (buf, size);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
			return buf;
		}

		private static NGTcp2.ConnectionID make_connection_id (size_t len) {
			var cid = NGTcp2.ConnectionID () {
				datalen = len,
			};
			NGTcp2.ConnectionID * mutable_cid = &cid;
			OpenSSL.Rng.generate (mutable_cid->data[:len]);
			return cid;
		}

		private static NGTcp2.Timestamp make_timestamp () {
			return get_monotonic_time () * NGTcp2.MICROSECONDS;
		}
	}
}
