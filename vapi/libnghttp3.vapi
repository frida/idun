[CCode (cheader_filename = "nghttp3/nghttp3.h", lower_case_cprefix = "nghttp3_", gir_namespace = "NGHttp3", gir_version = "1.0")]
namespace NGHttp3 {
	[Compact]
	[CCode (cname = "nghttp3_conn", cprefix = "nghttp3_conn_", free_function = "nghttp3_conn_del")]
	public class Connection {
		[CCode (cname = "nghttp3_conn_client_new")]
		public static int make_client (out Connection conn, Callbacks callbacks, Settings settings,
			MemoryAllocator? mem, void * user_data);

		public int bind_control_stream (int64 stream_id);
		public int bind_qpack_streams (int64 encoder_stream_id, int64 decoder_stream_id);

		[CCode (cname = "nghttp3_conn_read_stream")]
		public ssize_t read_stream (int64 stream_id, uint8[] src, int fin);

		[CCode (cname = "nghttp3_conn_writev_stream")]
		public ssize_t writev_stream (out int64 stream_id, out int fin,
			[CCode (array_length = false)] Vector[] vec, size_t veccnt);

		public int add_write_offset (int64 stream_id, size_t n);
		public int add_ack_offset (int64 stream_id, uint64 n);

		public int submit_request (int64 stream_id,
			[CCode (array_length = false)] Header[] nva, size_t nvlen,
			DataReader? dr, void * stream_user_data);

		public int close_stream (int64 stream_id, uint64 app_error_code);
		public int set_stream_user_data (int64 stream_id, void * stream_user_data);
	}

	[CCode (cname = "nghttp3_nv", has_type_id = false)]
	public struct Header {
		[CCode (array_length_cname = "namelen")]
		public unowned uint8[] name;
		[CCode (array_length_cname = "valuelen")]
		public unowned uint8[] value;
		public uint8 flags;
	}

	[SimpleType]
	[CCode (cname = "nghttp3_vec", has_type_id = false)]
	public struct Vector {
		public uint8 * base;
		public size_t len;
	}

	[CCode (cname = "nghttp3_data_reader", has_type_id = false)]
	public struct DataReader {
		public ReadDataCallback read_data;
	}

	[CCode (cname = "nghttp3_read_data_callback", has_target = false)]
	public delegate ssize_t ReadDataCallback (Connection conn, int64 stream_id,
		[CCode (array_length = false)] Vector[] vec, size_t veccnt, out uint32 pflags,
		void * conn_user_data, void * stream_user_data);

	[Compact]
	[CCode (cname = "nghttp3_rcbuf", cprefix = "nghttp3_rcbuf_")]
	public class ReferenceCountedBuffer {
		[CCode (cname = "nghttp3_rcbuf_get_buf")]
		public Vector get_buffer ();
	}

	[CCode (cname = "nghttp3_settings", has_type_id = false, destroy_function = "")]
	public struct Settings {
		[CCode (cname = "nghttp3_settings_default")]
		public Settings.make_default ();
	}

	[CCode (cname = "nghttp3_callbacks", has_type_id = false, destroy_function = "")]
	public struct Callbacks {
		public AckedStreamData acked_stream_data;
		public StreamClose stream_close;
		public RecvData recv_data;
		public DeferredConsume deferred_consume;
		public BeginHeaders begin_headers;
		public RecvHeader recv_header;
		public EndHeaders end_headers;
		public BeginHeaders begin_trailers;
		public RecvHeader recv_trailer;
		public EndHeaders end_trailers;
		public StopSending stop_sending;
		public EndStream end_stream;
		public ResetStream reset_stream;
	}

	[CCode (cname = "nghttp3_acked_stream_data", has_target = false)]
	public delegate int AckedStreamData (Connection conn, int64 stream_id, uint64 datalen,
		void * conn_user_data, void * stream_user_data);
	[CCode (cname = "nghttp3_stream_close", has_target = false)]
	public delegate int StreamClose (Connection conn, int64 stream_id, uint64 app_error_code,
		void * conn_user_data, void * stream_user_data);
	[CCode (cname = "nghttp3_recv_data", has_target = false)]
	public delegate int RecvData (Connection conn, int64 stream_id,
		[CCode (array_length_type = "size_t")] uint8[] data, void * conn_user_data,
		void * stream_user_data);
	[CCode (cname = "nghttp3_deferred_consume", has_target = false)]
	public delegate int DeferredConsume (Connection conn, int64 stream_id, size_t consumed,
		void * conn_user_data, void * stream_user_data);
	[CCode (cname = "nghttp3_begin_headers", has_target = false)]
	public delegate int BeginHeaders (Connection conn, int64 stream_id, void * conn_user_data,
		void * stream_user_data);
	[CCode (cname = "nghttp3_recv_header", has_target = false)]
	public delegate int RecvHeader (Connection conn, int64 stream_id, int32 token,
		ReferenceCountedBuffer name, ReferenceCountedBuffer value, uint8 flags,
		void * conn_user_data, void * stream_user_data);
	[CCode (cname = "nghttp3_end_headers", has_target = false)]
	public delegate int EndHeaders (Connection conn, int64 stream_id, int fin, void * conn_user_data,
		void * stream_user_data);
	[CCode (cname = "nghttp3_stop_sending", has_target = false)]
	public delegate int StopSending (Connection conn, int64 stream_id, uint64 app_error_code,
		void * conn_user_data, void * stream_user_data);
	[CCode (cname = "nghttp3_end_stream", has_target = false)]
	public delegate int EndStream (Connection conn, int64 stream_id, void * conn_user_data,
		void * stream_user_data);
	[CCode (cname = "nghttp3_reset_stream", has_target = false)]
	public delegate int ResetStream (Connection conn, int64 stream_id, uint64 app_error_code,
		void * conn_user_data, void * stream_user_data);

	[Compact]
	[CCode (cname = "nghttp3_mem")]
	public class MemoryAllocator {
	}

	[CCode (cname = "NGHTTP3_NV_FLAG_NONE")]
	public const uint8 NV_FLAG_NONE;

	[CCode (cname = "nghttp3_err_is_fatal")]
	public bool err_is_fatal (int liberr);
	public unowned string strerror (int liberr);
}
