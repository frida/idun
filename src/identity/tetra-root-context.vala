using Efni;

namespace Idun {
	/**
	 * The registration binding that the pair-tetra root derivation commits to: both
	 * peers' handles, APNs push tokens and device signing keys, and the responder's
	 * Kyber public key. These are fixed for the lifetime of a session; the ratchet
	 * points and the initiator's Kyber encapsulation change per message, so they are
	 * supplied separately when the transcript is assembled. The initiator is the peer
	 * that placed the call and carries the Kyber encapsulation; the responder is the one
	 * reached by its prekey.
	 */
	public sealed class TetraRootContext : Object {
		public Bytes initiator_uri {
			get;
			construct;
		}

		public Bytes initiator_push_token {
			get;
			construct;
		}

		public Bytes initiator_signing {
			get;
			construct;
		}

		public Bytes responder_uri {
			get;
			construct;
		}

		public Bytes responder_push_token {
			get;
			construct;
		}

		public Bytes responder_signing {
			get;
			construct;
		}

		public Bytes responder_kyber_public {
			get;
			construct;
		}

		public TetraRootContext (Bytes initiator_uri, Bytes initiator_push_token, Bytes initiator_signing,
				Bytes responder_uri, Bytes responder_push_token, Bytes responder_signing,
				Bytes responder_kyber_public) {
			Object (
				initiator_uri: initiator_uri,
				initiator_push_token: initiator_push_token,
				initiator_signing: initiator_signing,
				responder_uri: responder_uri,
				responder_push_token: responder_push_token,
				responder_signing: responder_signing,
				responder_kyber_public: responder_kyber_public);
		}

		public uint8[] serialize () {
			var writer = new ProtobufWriter ();
			writer
				.append_bytes (1, initiator_uri.get_data ())
				.append_bytes (2, initiator_push_token.get_data ())
				.append_bytes (3, initiator_signing.get_data ())
				.append_bytes (4, responder_uri.get_data ())
				.append_bytes (5, responder_push_token.get_data ())
				.append_bytes (6, responder_signing.get_data ())
				.append_bytes (7, responder_kyber_public.get_data ());
			return writer.data;
		}

		public static TetraRootContext restore (uint8[] data) throws Efni.Error {
			Bytes? initiator_uri = null;
			Bytes? initiator_push_token = null;
			Bytes? initiator_signing = null;
			Bytes? responder_uri = null;
			Bytes? responder_push_token = null;
			Bytes? responder_signing = null;
			Bytes? responder_kyber_public = null;

			var reader = new ProtobufReader (data);
			while (reader.has_more) {
				uint8 wire_type;
				switch (reader.read_field (out wire_type)) {
					case 1:
						initiator_uri = new Bytes (reader.read_bytes ());
						break;
					case 2:
						initiator_push_token = new Bytes (reader.read_bytes ());
						break;
					case 3:
						initiator_signing = new Bytes (reader.read_bytes ());
						break;
					case 4:
						responder_uri = new Bytes (reader.read_bytes ());
						break;
					case 5:
						responder_push_token = new Bytes (reader.read_bytes ());
						break;
					case 6:
						responder_signing = new Bytes (reader.read_bytes ());
						break;
					case 7:
						responder_kyber_public = new Bytes (reader.read_bytes ());
						break;
					default:
						reader.skip (wire_type);
						break;
				}
			}

			if (initiator_uri == null || initiator_push_token == null || initiator_signing == null ||
					responder_uri == null || responder_push_token == null || responder_signing == null ||
					responder_kyber_public == null)
				throw new Efni.Error.PROTOCOL ("Incomplete pair-tetra root context");

			return new TetraRootContext (initiator_uri, initiator_push_token, initiator_signing,
				responder_uri, responder_push_token, responder_signing, responder_kyber_public);
		}
	}
}
