namespace Idun {
	/**
	 * A keyed blob a participant shares with the call over the relay: its media prekey,
	 * media key or session key, carried to a specific receiver and tagged with the type
	 * that tells the receiver how to use it. Idun both sends its own and reads its peers'.
	 */
	public sealed class FaceTimeMaterial : Object {
		public int material_type { get; set; }
		public uint8[] material_id { get; set; }
		public uint8[] material_content { get; set; }
		public int64 owner_participant_id { get; set; }
		public int64 receiver_participant_id { get; set; }

		public const int PREKEY = 11;
		public const int AVCBLOB = 12;
		public const int MEDIA_KEY = 13;
		public const int SESSION_KEY = 14;
	}

	/**
	 * The HTTP/3 control messages a device exchanges with the QuickRelay once its QUIC
	 * link is up: the allocbind that joins the relay and declares the device's QUIC
	 * channels, and the material posts that carry the call's keys. All ride a single
	 * envelope protobuf whose set field names the message.
	 */
	public sealed class FaceTimeRelayProtocol {
		private const int ALLOCBIND_REQUEST = 1;
		private const int ALLOCBIND_RESPONSE = 2;
		private const int PUTMATERIAL_REQUEST = 24;
		private const int PUTMATERIAL_INDICATION = 26;
		private const int GETMATERIAL_RESPONSE = 28;
		private const int ALLOCBIND_MATERIALS_FIELD = 15;
		private const int MATERIALS_FIELD = 1;

		private const int SERVICE_ID = 4096;
		private const int CAPABILITIES = 114129391;
		private const int CHANNEL_BINDING_INFO = 528;
		private const int MAX_CONCURRENT_STREAMS = 6;
		private const int STATE_FLAGS = 2;
		private const int ALLOCATE_REASON = 1;
		private const string CLIENT_OS_VERSION = "macOS,27.0,26A428";
		private const string CLIENT_HW_VERSION = "Mac17,2";

		public static uint8[] build_allocbind (uint8[] avc_connection_id, uint8[] ids_connection_id,
				FaceTimeMaterial[] materials) {
			var subscription = new ProtobufWriter ()
				.append_varint (1, 1);

			var request = new ProtobufWriter ()
				.append_varint (1, SERVICE_ID)
				.append_bytes (2, CLIENT_OS_VERSION.data)
				.append_bytes (3, CLIENT_HW_VERSION.data)
				.append_varint (4, CAPABILITIES)
				.append_bytes (6, subscription.data)
				.append_varint (8, MAX_CONCURRENT_STREAMS)
				.append_varint (9, CHANNEL_BINDING_INFO)
				.append_bytes (11, quic_connection_info (0, avc_connection_id))
				.append_bytes (11, quic_connection_info (1, ids_connection_id))
				.append_varint (12, STATE_FLAGS)
				.append_varint (14, ALLOCATE_REASON);
			foreach (FaceTimeMaterial material in materials)
				request.append_bytes (15, encode_material (material));
			request.append_bytes (21, new ProtobufWriter ()
				.append_varint (1, 1)
				.append_varint (2, 2)
				.data);
			append_session_experiments (request);

			return new ProtobufWriter ().append_bytes (ALLOCBIND_REQUEST, request.data).data;
		}

		private static void append_session_experiments (ProtobufWriter request) {
			request.append_bytes (26, integer_experiment ("h2fdv2", 0));
			request.append_bytes (26, string_experiment ("qrse_cnt", "NO"));
			request.append_bytes (26, integer_experiment ("und2", 0));
			request.append_bytes (26, integer_experiment ("qrse_wsep", 1));
			request.append_bytes (26, string_experiment ("msa", "M"));
			request.append_bytes (26, string_experiment ("qrse_pop", "sto"));
			request.append_bytes (26, integer_experiment ("h2fd", 1));
		}

		private static uint8[] integer_experiment (string name, int value) {
			return new ProtobufWriter ()
				.append_varint (2, value)
				.append_bytes (5, name.data)
				.data;
		}

		private static uint8[] string_experiment (string name, string value) {
			return new ProtobufWriter ()
				.append_bytes (3, value.data)
				.append_bytes (5, name.data)
				.data;
		}

		public static uint8[] build_put_material (FaceTimeMaterial[] materials) {
			var request = new ProtobufWriter ();
			foreach (FaceTimeMaterial material in materials)
				request.append_bytes (1, encode_material (material));
			return new ProtobufWriter ().append_bytes (PUTMATERIAL_REQUEST, request.data).data;
		}

		public static FaceTimeMaterial[] read_materials (uint8[] envelope) throws Efni.Error {
			var materials = new Gee.ArrayList<FaceTimeMaterial> ();
			var reader = new ProtobufReader (envelope);
			while (reader.has_more) {
				uint8 wire_type;
				int field = reader.read_field (out wire_type);
				if (wire_type != 2) {
					reader.skip (wire_type);
					continue;
				}
				if (field == ALLOCBIND_RESPONSE)
					collect_materials (reader.read_bytes (), ALLOCBIND_MATERIALS_FIELD, materials);
				else if (field == GETMATERIAL_RESPONSE || field == PUTMATERIAL_INDICATION
						|| field == PUTMATERIAL_REQUEST)
					collect_materials (reader.read_bytes (), MATERIALS_FIELD, materials);
				else
					reader.skip (wire_type);
			}
			return materials.to_array ();
		}

		private static void collect_materials (uint8[] message, int material_field,
				Gee.List<FaceTimeMaterial> into) throws Efni.Error {
			var reader = new ProtobufReader (message);
			while (reader.has_more) {
				uint8 wire_type;
				int field = reader.read_field (out wire_type);
				if (field == material_field && wire_type == 2)
					into.add (decode_material (reader.read_bytes ()));
				else
					reader.skip (wire_type);
			}
		}

		private static uint8[] quic_connection_info (int type, uint8[] connection_id) {
			return new ProtobufWriter ()
				.append_varint (1, type)
				.append_bytes (2, connection_id)
				.data;
		}

		private static uint8[] encode_material (FaceTimeMaterial material) {
			var info = new ProtobufWriter ()
				.append_bytes (1, material.material_id)
				.append_varint (2, material.material_type)
				.append_bytes (3, material.material_content)
				.append_varint (4, 0);

			return new ProtobufWriter ()
				.append_varint (1, material.owner_participant_id)
				.append_varint (2, material.receiver_participant_id)
				.append_bytes (3, info.data)
				.data;
		}

		private static FaceTimeMaterial decode_material (uint8[] message) throws Efni.Error {
			var material = new FaceTimeMaterial ();
			var reader = new ProtobufReader (message);
			while (reader.has_more) {
				uint8 wire_type;
				int field = reader.read_field (out wire_type);
				switch (field) {
					case 1:
						material.owner_participant_id = (int64) reader.read_varint ();
						break;
					case 2:
						material.receiver_participant_id = (int64) reader.read_varint ();
						break;
					case 3:
						decode_material_info (reader.read_bytes (), material);
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}
			return material;
		}

		private static void decode_material_info (uint8[] message, FaceTimeMaterial material)
				throws Efni.Error {
			var reader = new ProtobufReader (message);
			while (reader.has_more) {
				uint8 wire_type;
				int field = reader.read_field (out wire_type);
				switch (field) {
					case 1:
						material.material_id = reader.read_bytes ();
						break;
					case 2:
						material.material_type = (int) reader.read_varint ();
						break;
					case 3:
						material.material_content = reader.read_bytes ();
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}
		}
	}
}
