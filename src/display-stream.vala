using Efni;

namespace Idun {
	public sealed class DisplayStream : Object {
		public signal void started ();
		public signal void closed (Efni.Error? error);
		public signal void rtp (Bytes data);
		public signal void rtcp (Bytes data);

		public uint width {
			get;
			private set;
		}

		public uint height {
			get;
			private set;
		}

		public uint framerate {
			get;
			private set;
		}

		public uint payload_type {
			get;
			private set;
		}

		public uint clock_rate {
			get;
			private set;
			default = 90000;
		}

		public uint32 local_ssrc {
			get;
			private set;
		}

		public uint32 remote_ssrc {
			get;
			private set;
		}

		/**
		 * The H.264 parameter sets (SPS and PPS NAL units) announced by the device.
		 *
		 * The device sends these out-of-band rather than in the RTP stream, so consumers must
		 * feed them to the decoder themselves. Updated whenever the device announces new ones.
		 */
		public Gee.List<Bytes> parameter_sets {
			get;
			private set;
			default = new Gee.ArrayList<Bytes> ();
		}

		/**
		 * The AVCDecoderConfigurationRecord announced by the device, if any.
		 */
		public Bytes? codec_data {
			get;
			private set;
		}

		private Tunnel tunnel;
		private DisplayService service;
		private UdpSocket socket;
		private StreamConfig config;
		private DatagramBasedSource rx_source;
		private uint8[] rx_buf = new uint8[MAX_DATAGRAM_SIZE];
		private bool is_closed = false;
		private MainContext main_context;
		private Cancellable io_cancellable = new Cancellable ();

		private const size_t MAX_DATAGRAM_SIZE = 65535;
		private const uint8 RTCP_PACKET_TYPE_LOWEST = 200;
		private const uint8 RTCP_PACKET_TYPE_HIGHEST = 207;
		private const size_t RTP_HEADER_SIZE = 12;
		private const uint8 NAL_TYPE_PARAMETER_SETS = 18;

		public static async DisplayStream open (Device device, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var tunnel = yield device.find_tunnel (cancellable);
			if (tunnel == null)
				throw new Efni.Error.NOT_SUPPORTED ("Display streaming requires a CoreDevice tunnel");

			var info = yield CoreDeviceInfoService.open (device, cancellable);
			var displays = yield info.query_displays (cancellable);
			info.close ();
			DisplayInfo display = displays.first_match (d => d.primary);

			var service = yield DisplayService.open (device, cancellable);

			return new DisplayStream (tunnel, service, display);
		}

		private DisplayStream (Tunnel tunnel, DisplayService service, DisplayInfo display) {
			this.tunnel = tunnel;
			this.service = service;
			width = display.width;
			height = display.height;
			service.closed.connect (on_service_closed);
		}

		public async void start (Cancellable? cancellable = null) throws Efni.Error, IOError {
			main_context = MainContext.ref_thread_default ();

			socket = tunnel.create_udp_socket ();
			InetSocketAddress local_address = socket.get_local_address ();
			InetSocketAddress remote_address = tunnel.make_remote_address (0);

			uint32 our_ssrc = Random.next_int ();
			try {
				config = yield service.start_media_stream (local_address, remote_address, make_negotiation_offer (our_ssrc),
					cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}
			framerate = config.framerate;
			payload_type = config.payload_type;
			local_ssrc = config.remote_ssrc;
			remote_ssrc = config.local_ssrc;

			started ();

			rx_source = socket.datagram_based.create_source (IOCondition.IN, io_cancellable);
			rx_source.set_callback (on_socket_readable);
			rx_source.attach (main_context);
		}

		public async void close (Cancellable? cancellable = null) throws IOError {
			if (is_closed)
				return;
			is_closed = true;

			io_cancellable.cancel ();

			if (config != null) {
				rx_source.destroy ();
				try {
					yield service.stop_media_stream (config.remote_ssrc, cancellable);
				} catch (Efni.Error e) {
				}
			}

			service.close ();
		}

		public void send_rtcp (Bytes data) throws Efni.Error, IOError {
			if (config == null)
				throw new Efni.Error.INVALID_OPERATION ("Stream not started");
			Udp.send_to (data.get_data (), tunnel.make_remote_address (config.source_port), socket.datagram_based, io_cancellable);
		}

		private bool on_socket_readable (DatagramBased datagram_based, IOCondition condition) {
			InetSocketAddress sender;
			size_t n;
			try {
				n = Udp.recv (rx_buf, datagram_based, io_cancellable, out sender);
			} catch (GLib.Error e) {
				return Source.REMOVE;
			}

			unowned uint8[] packet = rx_buf[:n];
			if (packet[1] >= RTCP_PACKET_TYPE_LOWEST && packet[1] <= RTCP_PACKET_TYPE_HIGHEST)
				rtcp (new Bytes (packet));
			else if (!try_consume_parameter_sets (packet))
				rtp (new Bytes (packet));

			return Source.CONTINUE;
		}

		private bool try_consume_parameter_sets (uint8[] packet) {
			size_t payload_offset = compute_rtp_payload_offset (packet);
			if (payload_offset == 0 || payload_offset >= packet.length)
				return false;
			if ((packet[payload_offset] & 0x1f) != NAL_TYPE_PARAMETER_SETS)
				return false;

			Bytes? record = find_avcc_record (packet[payload_offset:]);
			if (record == null)
				return true;

			Gee.List<Bytes>? sets = parse_avcc_record (record);
			if (sets == null)
				return true;

			parameter_sets = sets;
			codec_data = record;

			return true;
		}

		private static size_t compute_rtp_payload_offset (uint8[] packet) {
			if (packet.length < RTP_HEADER_SIZE)
				return 0;

			uint8 first = packet[0];
			if ((first >> 6) != 2)
				return 0;
			uint csrc_count = first & 0x0f;
			bool has_extension = (first & 0x10) != 0;

			size_t offset = RTP_HEADER_SIZE + (csrc_count * 4);
			if (has_extension) {
				if (offset + 4 > packet.length)
					return 0;
				uint extension_words = ((uint) packet[offset + 2] << 8) | packet[offset + 3];
				offset += 4 + (extension_words * 4);
			}

			return offset;
		}

		private static Bytes? find_avcc_record (uint8[] payload) {
			for (size_t i = 4; i + 4 <= payload.length; i++) {
				if (payload[i] != 'a' || payload[i + 1] != 'v' || payload[i + 2] != 'c' || payload[i + 3] != 'C')
					continue;
				size_t box_start = i - 4;
				size_t box_size = ((size_t) payload[box_start] << 24) | ((size_t) payload[box_start + 1] << 16) |
					((size_t) payload[box_start + 2] << 8) | payload[box_start + 3];
				if (box_size < 8 || box_start + box_size > payload.length)
					return null;
				return new Bytes (payload[box_start + 8:box_start + box_size]);
			}
			return null;
		}

		private static Gee.List<Bytes>? parse_avcc_record (Bytes record) {
			unowned uint8[] data = record.get_data ();
			if (data.length < 7 || data[0] != 1)
				return null;

			var sets = new Gee.ArrayList<Bytes> ();
			size_t offset = 5;

			uint num_sps = data[offset++] & 0x1f;
			if (!read_parameter_sets (data, ref offset, num_sps, sets))
				return null;

			if (offset >= data.length)
				return null;
			uint num_pps = data[offset++];
			if (!read_parameter_sets (data, ref offset, num_pps, sets))
				return null;

			return sets;
		}

		private static bool read_parameter_sets (uint8[] data, ref size_t offset, uint count, Gee.List<Bytes> sets) {
			for (uint i = 0; i != count; i++) {
				if (offset + 2 > data.length)
					return false;
				size_t size = ((size_t) data[offset] << 8) | data[offset + 1];
				offset += 2;
				if (offset + size > data.length)
					return false;
				sets.add (new Bytes (data[offset:offset + size]));
				offset += size;
			}
			return true;
		}

		private void on_service_closed (Efni.Error? error) {
			closed (error);
		}

		private static Bytes make_negotiation_offer (uint32 local_ssrc) throws Efni.Error {
			var offer = new Plist ();
			offer.set_string ("avcMediaStreamOptionCallID", Uuid.string_random ().up ());
			offer.set_integer ("avcMediaStreamNegotiatorMode", AvConference.MODE_COREDEVICE_SCREEN_SHARING);
			offer.set_integer ("avcMediaStreamNegotiatorDirection", AvConference.DIRECTION_RECEIVE);
			offer.set_bytes ("avcMediaStreamNegotiatorMediaBlob", Zlib.compress (AvConference.make_screen_blob (local_ssrc)));
			return new Bytes (offer.to_binary ());
		}

		private class StreamConfig {
			public uint32 remote_ssrc;
			public uint32 local_ssrc;
			public uint16 source_port;
			public uint framerate;
			public uint payload_type;
		}

		private class DisplayService : TrustedService {
			public signal void closed (Efni.Error? error);

			private const uint64 CLIENT_SUPPORTED_FEATURES = 972;
			private const uint64 START_TIMEOUT = 10;

			public static async DisplayService open (Device device, Cancellable? cancellable) throws Efni.Error, IOError {
				var channel = yield device.open_tcp_channel ("com.apple.coredevice.displayservice", ALLOW_TUNNEL, cancellable);
				var service = new DisplayService (channel.stream);

				try {
					yield service.init_async (Priority.DEFAULT, cancellable);
				} catch (GLib.Error e) {
					throw_api_error (e);
				}

				return service;
			}

			private DisplayService (IOStream stream) {
				Object (stream: stream);
			}

			public async StreamConfig start_media_stream (InetSocketAddress receiver, InetSocketAddress sender, Bytes negotiation_offer,
					Cancellable? cancellable) throws Efni.Error, IOError {
				var call_id = new RandomUuid ();
				var session_id = new RandomUuid ();

				Bytes input = new XpcObjectBuilder ()
					.begin_dictionary ()
						.set_member_name ("receiverIP")
						.add_string_value (receiver.get_address ().to_string ())
						.set_member_name ("receiverPort")
						.add_uint64_value (receiver.get_port ())
						.set_member_name ("senderIP")
						.add_string_value (sender.get_address ().to_string ())
						.set_member_name ("timeout")
						.add_uint64_value (START_TIMEOUT)
						.set_member_name ("type")
						.add_string_value ("video")
						.set_member_name ("direction")
						.add_string_value ("output")
						.set_member_name ("negotiatorOffer")
						.add_data_value (negotiation_offer)
						.set_member_name ("clientSupportedFeatures")
						.add_uint64_value (CLIENT_SUPPORTED_FEATURES)
						.set_member_name ("options")
						.begin_dictionary ()
							.set_member_name ("avcMediaStreamOptionClientName")
							.begin_dictionary ()
								.set_member_name ("string")
								.add_string_value ("CoreDevice")
							.end_dictionary ()
							.set_member_name ("avcMediaStreamOptionCallID")
							.begin_dictionary ()
								.set_member_name ("uuid")
								.add_uuid_value (call_id.bytes)
							.end_dictionary ()
							.set_member_name ("avcMediaStreamOptionClientSessionID")
							.begin_dictionary ()
								.set_member_name ("uuid")
								.add_uuid_value (session_id.bytes)
							.end_dictionary ()
						.end_dictionary ()
					.end_dictionary ()
					.build ();
				var response = yield invoke ("com.apple.coredevice.feature.startmediastream", input, cancellable);

				response.read_member ("connection").read_member ("streamConfig");
				var config = new StreamConfig ();
				config.remote_ssrc = (uint32) response.read_member ("RemoteSSRC").get_uint64_value ();
				response.end_member ();
				config.local_ssrc = (uint32) response.read_member ("LocalSSRC").get_uint64_value ();
				response.end_member ();
				config.source_port = (uint16) response.read_member ("SourcePort").get_uint64_value ();
				response.end_member ();
				config.framerate = (uint) response.read_member ("Framerate").get_uint64_value ();
				response.end_member ();
				config.payload_type = (uint) response.read_member ("RxPayloadType").get_uint64_value ();
				response.end_member ();
				return config;
			}

			public async void stop_media_stream (uint32 remote_ssrc, Cancellable? cancellable) throws Efni.Error, IOError {
				Bytes input = new XpcObjectBuilder ()
					.begin_dictionary ()
						.set_member_name ("stopAll")
						.add_bool_value (false)
						.set_member_name ("identifiers")
						.begin_array ()
							.add_uint64_value (remote_ssrc)
						.end_array ()
					.end_dictionary ()
					.build ();
				yield invoke ("com.apple.coredevice.feature.stopmediastream", input, cancellable);
			}
		}

		private class RandomUuid {
			public uint8[] bytes = new uint8[16];

			public RandomUuid () {
				string hex = Uuid.string_random ().replace ("-", "");
				for (int i = 0; i != 16; i++)
					bytes[i] = (uint8) uint.parse (hex.substring (2 * i, 2), 16);
			}
		}
	}

	namespace AvConference {
		public const int64 MODE_COREDEVICE_SCREEN_SHARING = 5;
		public const int64 DIRECTION_RECEIVE = 1;

		private const uint64 PAYLOAD_H264 = 123;
		private const uint64 H264_PARAMETER_SET = 1;
		private const uint64 ALL_FORMATS = 0x00ffffff;
		private const string USER_AGENT = "Viceroy 1.7.0";
		private const uint64 BLOB_VERSION = 2;
		private const uint64 NTP_EPOCH_OFFSET = 2208988800;

		public Bytes make_screen_blob (uint32 ssrc) {
			Bytes rule_collection = new ProtobufBuilder ()
				.append_varint (RuleCollection.TRANSPORT, 1)
				.append_varint (RuleCollection.OPERATION, 1)
				.append_varint (RuleCollection.FORMATS, ALL_FORMATS)
				.build ();
			Bytes payload_settings = new ProtobufBuilder ()
				.append_varint (PayloadSettings.PAYLOAD, PAYLOAD_H264)
				.append_bytes (PayloadSettings.RULE_COLLECTIONS, rule_collection)
				.append_varint (PayloadSettings.PARAMETER_SET, H264_PARAMETER_SET)
				.build ();
			Bytes screen_settings = new ProtobufBuilder ()
				.append_varint (VideoSettings.RTP_SSRC, ssrc)
				.append_varint (VideoSettings.ALLOW_RTCP_FEEDBACK, 1)
				.append_bytes (VideoSettings.PAYLOAD_COLLECTIONS, payload_settings)
				.build ();
			return new ProtobufBuilder ()
				.append_varint (NegotiationBlob.ALLOW_DYNAMIC_MAX_BITRATE, 1)
				.append_varint (NegotiationBlob.ALLOWS_CONTENTS_CHANGE_WITH_ASPECT_PRESERVATION, 1)
				.append_bytes (NegotiationBlob.SCREEN_SETTINGS, screen_settings)
				.append_string (NegotiationBlob.USER_AGENT, USER_AGENT)
				.append_varint (NegotiationBlob.NTP_TIME, ntp_now ())
				.append_varint (NegotiationBlob.BLOB_VERSION, BLOB_VERSION)
				.build ();
		}

		private uint64 ntp_now () {
			int64 now = get_real_time ();
			uint64 seconds = (now / 1000000) + NTP_EPOCH_OFFSET;
			uint64 fraction = (((uint64) (now % 1000000)) << 32) / 1000000;
			return (seconds << 32) | fraction;
		}

		private enum NegotiationBlob {
			ALLOW_DYNAMIC_MAX_BITRATE = 1,
			ALLOWS_CONTENTS_CHANGE_WITH_ASPECT_PRESERVATION = 2,
			SCREEN_SETTINGS = 5,
			USER_AGENT = 6,
			NTP_TIME = 13,
			BLOB_VERSION = 14,
		}

		private enum VideoSettings {
			RTP_SSRC = 1,
			ALLOW_RTCP_FEEDBACK = 2,
			PAYLOAD_COLLECTIONS = 3,
		}

		private enum PayloadSettings {
			PAYLOAD = 1,
			RULE_COLLECTIONS = 2,
			PARAMETER_SET = 4,
		}

		private enum RuleCollection {
			TRANSPORT = 1,
			OPERATION = 2,
			FORMATS = 3,
		}

		private class ProtobufBuilder {
			private ByteArray buffer = new ByteArray ();

			public unowned ProtobufBuilder append_varint (uint field_number, uint64 val) {
				append_raw_varint ((field_number << 3) | WireType.VARINT);
				append_raw_varint (val);
				return this;
			}

			public unowned ProtobufBuilder append_string (uint field_number, string val) {
				return append_bytes (field_number, new Bytes (val.data));
			}

			public unowned ProtobufBuilder append_bytes (uint field_number, Bytes val) {
				append_raw_varint ((field_number << 3) | WireType.LENGTH_DELIMITED);
				append_raw_varint (val.length);
				buffer.append (val.get_data ());
				return this;
			}

			public Bytes build () {
				return ByteArray.free_to_bytes ((owned) buffer);
			}

			private void append_raw_varint (uint64 val) {
				uint64 remaining = val;
				do {
					uint8 b = (uint8) (remaining & 0x7f);
					remaining >>= 7;
					if (remaining != 0)
						b |= 0x80;
					buffer.append ({ b });
				} while (remaining != 0);
			}

			private enum WireType {
				VARINT = 0,
				LENGTH_DELIMITED = 2,
			}
		}
	}

	namespace Zlib {
		public Bytes compress (Bytes data) {
			var output = new MemoryOutputStream.resizable ();
			var compressor = new ConverterOutputStream (output, new ZlibCompressor (ZlibCompressorFormat.ZLIB, 9));
			try {
				compressor.write_all (data.get_data (), null);
				compressor.close ();
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
			return output.steal_as_bytes ();
		}
	}
}
