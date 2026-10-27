using Efni;
using OpenSSL;
using OpenSSL.Envelope;

namespace Idun {
	/**
	 * The media-plane key wrap a FaceTime call answer uses to hand its SRTP master keys
	 * to each peer. A master key is sealed to a peer's advertised ''rtmpk'' point by an
	 * ephemeral P-256 agreement, an HKDF-SHA256 whose info names the wrap and both public
	 * points, and an AES-256 key wrap. The sealed blob is the ephemeral point followed by
	 * the wrapped key.
	 */
	public sealed class FaceTimeMediaCrypto {
		private const int POINT_LENGTH = 65;
		private const int WRAP_KEY_LENGTH = 32;
		private const int SRTP_KEY_LENGTH = 30;
		private const int CONTROL_KEY_LENGTH = 32;
		private const string WRAP_INFO = "GFT-MKM-Wrapping";
		private const string CONTROL_INFO = "VCControlChannelV2";

		/**
		 * The media-key indicator a sender stamps on its streams, a short-format key
		 * identifier carrying the roll and ratchet counters and the sender's participant
		 * id so a receiver can tell which media key decrypts a packet.
		 */
		public static uint8[] media_key_indicator (int64 participant_id) {
			var indicator = new BufferBuilder (BIG_ENDIAN);
			indicator.append_uint16 (1 << 4);
			indicator.append_uint32 ((uint32) ((uint64) participant_id >> 32));
			indicator.append_uint8 (0);
			indicator.append_uint32 ((uint32) participant_id);
			indicator.append_uint32 (0);
			indicator.append_uint8 (0);
			return indicator.build ().get_data ();
		}

		/**
		 * The SRTP master key (key and salt) that protects one stream, derived from a
		 * media key and its salt for the stream's synchronisation source. Each SSRC takes
		 * its own key, so the sender's and each receiver's streams never share one.
		 */
		public static uint8[] media_stream_key (uint8[] media_key, uint8[] media_salt, uint32 ssrc)
				throws Efni.Error {
			var info = new BufferBuilder (LITTLE_ENDIAN);
			info.append_uint32 (ssrc);
			return TetraCrypto.hkdf_extract_and_expand (ShortName.sha256, media_key, media_salt,
				info.build ().get_data (), SRTP_KEY_LENGTH);
		}

		/**
		 * The key that protects a call's control channel between two participants, bound
		 * to both of their session-participant identifiers so each pair derives its own.
		 */
		public static uint8[] control_channel_key (uint8[] media_key, uint8[] media_salt,
				uint8[] our_uuid, uint8[] peer_uuid) throws Efni.Error {
			var info = new BufferBuilder ();
			info.append_data (CONTROL_INFO.data);
			info.append_data (our_uuid);
			info.append_data (peer_uuid);
			return TetraCrypto.hkdf_extract_and_expand (ShortName.sha256, media_key, media_salt,
				info.build ().get_data (), CONTROL_KEY_LENGTH);
		}

		public static uint8[] wrap_key_material (uint8[] peer_point, uint8[] material) throws Efni.Error {
			Bytes ephemeral = TetraCrypto.generate_key_agreement_key ();
			uint8[] point = TetraCrypto.public_key_point (ephemeral);
			uint8[] key = derive_wrap_key (TetraCrypto.ecdh (ephemeral, peer_point), peer_point, point);

			var sealed = new BufferBuilder ();
			sealed.append_data (point);
			sealed.append_data (aes_256_wrap (key, material));
			return sealed.build ().get_data ();
		}

		public static uint8[] unwrap_key_material (Bytes our_key_pem, uint8[] sealed) throws Efni.Error {
			uint8[] point = sealed[0 : POINT_LENGTH];
			uint8[] our_point = TetraCrypto.public_key_point (our_key_pem);
			uint8[] key = derive_wrap_key (TetraCrypto.ecdh (our_key_pem, point), our_point, point);

			return aes_256_unwrap (key, sealed[POINT_LENGTH : sealed.length]);
		}

		private static uint8[] derive_wrap_key (uint8[] shared_secret, uint8[] recipient_point,
				uint8[] ephemeral_point) throws Efni.Error {
			var info = new BufferBuilder ();
			info.append_data (WRAP_INFO.data);
			info.append_data (recipient_point[1 : POINT_LENGTH]);
			info.append_data (ephemeral_point[1 : POINT_LENGTH]);
			return TetraCrypto.hkdf_extract_and_expand (ShortName.sha256, shared_secret, new uint8[0],
				info.build ().get_data (), WRAP_KEY_LENGTH);
		}

		private static uint8[] aes_256_wrap (uint8[] key, uint8[] plaintext) throws Efni.Error {
			var ctx = new CipherContext ();
			if (ctx.encrypt_init_ex (Cipher.fetch (null, "AES-256-WRAP"), null, key, null) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to initialize AES-256 key wrap");

			var output = new uint8[plaintext.length + 8];
			int produced = 0;
			if (ctx.encrypt_update (output, ref produced, plaintext) != 1)
				throw new Efni.Error.PROTOCOL ("AES-256 key wrap failed");
			int final_len = 0;
			ctx.encrypt_final ((uint8[]) ((uint8 *) output + produced), ref final_len);
			return output[0 : produced + final_len];
		}

		private static uint8[] aes_256_unwrap (uint8[] key, uint8[] ciphertext) throws Efni.Error {
			var ctx = new CipherContext ();
			if (ctx.decrypt_init_ex (Cipher.fetch (null, "AES-256-WRAP"), null, key, null) != 1)
				throw new Efni.Error.PROTOCOL ("Unable to initialize AES-256 key unwrap");

			var output = new uint8[ciphertext.length];
			int produced = 0;
			if (ctx.decrypt_update (output, ref produced, ciphertext) != 1)
				throw new Efni.Error.PROTOCOL ("Media key unwrap authentication failed");
			int final_len = 0;
			if (ctx.decrypt_final ((uint8[]) ((uint8 *) output + produced), ref final_len) != 1)
				throw new Efni.Error.PROTOCOL ("Media key unwrap authentication failed");
			return output[0 : produced + final_len];
		}
	}
}
