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

		public static MessageIdentity load_or_generate (MessageIdentityStore store) throws Efni.Error {
			MessageIdentity? existing = store.load ();
			if (existing != null)
				return existing;

			var identity = generate ();
			store.save (identity);
			return identity;
		}

		public static MessageIdentity generate () {
			OpenSSL.Envelope.Key encryption = generate_rsa (1280);
			OpenSSL.Envelope.Key signing = new OpenSSL.Envelope.Key.generate_ec ("P-256");
			return new MessageIdentity (export_private_key (encryption), export_private_key (signing),
				new Bytes (public_blob (encryption, signing)));
		}

		public static MessageIdentity from_keys (Bytes encryption_key, Bytes signing_key) {
			OpenSSL.Envelope.Key encryption = load_private_key (encryption_key);
			OpenSSL.Envelope.Key signing = load_private_key (signing_key);
			return new MessageIdentity (encryption_key, signing_key, new Bytes (public_blob (encryption, signing)));
		}

		private static uint8[] public_blob (OpenSSL.Envelope.Key encryption, OpenSSL.Envelope.Key signing) {
			uint8[] rsa_public = legacy_public_der (encryption);
			uint8[] ec_point = tail (subject_public_key_info (signing), 65);

			var inner = new ByteArray ();
			inner.append (context (1, with_length_prefix (ec_point)));
			inner.append (context (2, with_length_prefix (rsa_public)));
			return sequence (inner.data);
		}

		private static OpenSSL.Envelope.Key load_private_key (Bytes pem) {
			var source = new OpenSSL.BasicIO.from_static_memory_buffer (pem.get_data ());
			return new OpenSSL.Envelope.Key.from_private_key_pem (source);
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

	/**
	 * Persists the messaging identity so it survives across runs. Reusing it is what
	 * keeps Idun a single stable device in the account: a fresh identity on every run
	 * re-registers as a new device, which spams the user's other devices with
	 * "Device Added" notices.
	 */
	public sealed class MessageIdentityStore : IdentityStore {
		public MessageIdentity? load () {
			Plist? plist = read ();
			if (plist == null)
				return null;
			try {
				return MessageIdentity.from_keys (plist.get_bytes ("encryptionKey"), plist.get_bytes ("signingKey"));
			} catch (PlistError e) {
				return null;
			}
		}

		public void save (MessageIdentity identity) throws Efni.Error {
			var plist = new Plist ();
			plist.set_bytes ("encryptionKey", identity.encryption_key);
			plist.set_bytes ("signingKey", identity.signing_key);
			write (plist);
		}

		protected override string filename () {
			return "message-identity.plist";
		}
	}
}
