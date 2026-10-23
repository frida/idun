using Efni;

namespace Idun {
	/**
	 * The device's long-lived messaging identity: an RSA encryption key and an EC
	 * signing key whose public halves are packed into the identity blob Idun
	 * advertises when it registers, and whose private halves decrypt and sign the
	 * pair-encrypted traffic the identity services exchange.
	 */
	public sealed class MessageIdentity : Object {
		public Bytes encryption_key {
			get;
			construct;
		}

		public Bytes signing_key {
			get;
			construct;
		}

		public Bytes public_key {
			get;
			construct;
		}

		private MessageIdentity (Bytes encryption_key, Bytes signing_key, Bytes public_key) {
			Object (encryption_key: encryption_key, signing_key: signing_key, public_key: public_key);
		}

		public static MessageIdentity generate () {
			OpenSSL.Envelope.Key encryption = generate_rsa (1280);
			OpenSSL.Envelope.Key signing = new OpenSSL.Envelope.Key.generate_ec ("P-256");

			uint8[] rsa_public = legacy_public_der (encryption);
			uint8[] ec_point = tail (subject_public_key_info (signing), 65);

			var inner = new ByteArray ();
			inner.append (context (1, with_length_prefix (ec_point)));
			inner.append (context (2, with_length_prefix (rsa_public)));
			uint8[] packed = sequence (inner.data);

			return new MessageIdentity (export_private_key (encryption), export_private_key (signing),
				new Bytes (packed));
		}

		private static OpenSSL.Envelope.Key generate_rsa (int bits) {
			var ctx = new OpenSSL.Envelope.KeyContext.for_key_type (OpenSSL.Envelope.KeyType.RSA);
			ctx.keygen_init ();
			ctx.set_rsa_keygen_bits (bits);
			OpenSSL.Envelope.Key? key = null;
			ctx.keygen (ref key);
			return key;
		}

		private static uint8[] legacy_public_der (OpenSSL.Envelope.Key key) {
			int length = key.to_legacy_public_der ();
			var der = new uint8[length];
			uint8* cursor = der;
			key.to_legacy_public_der (&cursor);
			return der;
		}

		private static uint8[] subject_public_key_info (OpenSSL.Envelope.Key key) {
			var sink = new OpenSSL.BasicIO (OpenSSL.BasicIOMethod.memory ());
			key.to_der (sink);
			unowned uint8[] data;
			long size = sink.get_mem_data (out data);
			data.length = (int) size;
			return data;
		}

		private static Bytes export_private_key (OpenSSL.Envelope.Key key) {
			var sink = new OpenSSL.BasicIO (OpenSSL.BasicIOMethod.memory ());
			OpenSSL.Envelope.write_private_key_pem (sink, key);
			unowned uint8[] data;
			long size = sink.get_mem_data (out data);
			data.length = (int) size;
			return new Bytes (data);
		}

		private static uint8[] sequence (uint8[] content) {
			var result = new ByteArray ();
			result.append ({ 0x30 });
			result.append (der_length (content.length));
			result.append (content);
			return result.data;
		}

		private static uint8[] context (uint8 tag, uint8[] content) {
			var result = new ByteArray ();
			result.append ({ 0x80 | tag });
			result.append (der_length (content.length));
			result.append (content);
			return result.data;
		}

		private static uint8[] with_length_prefix (uint8[] value) {
			var result = new uint8[2 + value.length];
			result[0] = (uint8) (value.length >> 8);
			result[1] = (uint8) (value.length & 0xff);
			Memory.copy ((uint8*) result + 2, value, value.length);
			return result;
		}

		private static uint8[] der_length (int length) {
			if (length < 0x80)
				return new uint8[] { (uint8) length };

			var encoded = new ByteArray ();
			for (int value = length; value != 0; value >>= 8)
				encoded.prepend ({ (uint8) (value & 0xff) });

			var result = new uint8[1 + encoded.len];
			result[0] = (uint8) (0x80 | encoded.len);
			Memory.copy ((uint8*) result + 1, encoded.data, encoded.len);
			return result;
		}

		private static uint8[] tail (uint8[] value, int count) {
			return value[value.length - count : value.length];
		}
	}
}
