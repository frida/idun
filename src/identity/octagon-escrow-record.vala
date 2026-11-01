using Efni;

namespace Idun {
	/**
	 * One of the account's escrow records, as the escrow proxy stores it: the metadata
	 * that ties the record to a specific bottle and device, the record's identifiers, and
	 * its viability. Idun fetches these to pick the bottle whose secret it will recover
	 * with the iCloud Security Code, then opens that bottle to rejoin Octagon trust.
	 */
	public sealed class OctagonEscrowRecord : Object {
		public string record_id {
			get;
			construct;
		}

		public string serial_number {
			get;
			construct;
		}

		public uint64 remaining_attempts {
			get;
			construct;
		}

		public OctagonEscrowMetadata metadata {
			get;
			construct;
		}

		public OctagonEscrowRecord (string record_id, string serial_number, uint64 remaining_attempts,
				OctagonEscrowMetadata metadata) {
			Object (record_id: record_id, serial_number: serial_number,
				remaining_attempts: remaining_attempts, metadata: metadata);
		}

		public static OctagonEscrowRecord parse (uint8[] data) throws Efni.Error {
			string record_id = "";
			string serial_number = "";
			uint64 remaining_attempts = 0;
			OctagonEscrowMetadata? metadata = null;

			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 2:
						remaining_attempts = reader.read_varint ();
						break;
					case 3:
						metadata = OctagonEscrowMetadata.parse (reader.read_bytes ());
						break;
					case 11:
						record_id = reader.read_string ();
						break;
					case 14:
						serial_number = reader.read_string ();
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}

			if (metadata == null)
				throw new Efni.Error.PROTOCOL ("Escrow record is missing its metadata");

			return new OctagonEscrowRecord (record_id, serial_number, remaining_attempts, metadata);
		}
	}

	/**
	 * The metadata inside an escrow record: which bottle it escrows, the escrow signing
	 * public key the bottle was sealed under, and the device serial that created it.
	 */
	public sealed class OctagonEscrowMetadata : Object {
		public string bottle_id {
			get;
			construct;
		}

		public Bytes escrowed_spki {
			get;
			construct;
		}

		public string serial {
			get;
			construct;
		}

		public OctagonEscrowMetadata (string bottle_id, Bytes escrowed_spki, string serial) {
			Object (bottle_id: bottle_id, escrowed_spki: escrowed_spki, serial: serial);
		}

		public static OctagonEscrowMetadata parse (uint8[] data) throws Efni.Error {
			string bottle_id = "";
			Bytes escrowed_spki = new Bytes ({});
			string serial = "";

			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 4:
						bottle_id = reader.read_string ();
						break;
					case 6:
						escrowed_spki = new Bytes (reader.read_bytes ());
						break;
					case 9:
						serial = reader.read_string ();
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}

			return new OctagonEscrowMetadata (bottle_id, escrowed_spki, serial);
		}
	}
}
