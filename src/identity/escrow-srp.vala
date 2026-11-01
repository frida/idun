using Efni;

namespace Idun {
	/**
	 * The SRP-6a client the escrow proxy's RECOVER flow runs on: it proves knowledge of the
	 * iCloud Security Code (the escrow secret) without revealing it, and derives the session
	 * key the escrowed record is sealed under. RFC 5054 2048-bit group, SHA-256, with the
	 * ephemeral public values hashed in their minimal (trimmed) big-endian form — the exact
	 * convention Apple's escrow proxy verifies against.
	 */
	public sealed class EscrowSrpSession : Object {
		public uint8[] shared_key { get; private set; }
		public uint8[] client_proof { get; private set; }

		private const string N_HEX =
			"AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
			"A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
			"E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
			"55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
			"CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
			"544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
			"AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
			"94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";
		private const int N_LENGTH = 256;

		private OpenSSL.BigNumber n;
		private OpenSSL.BigNumber g;
		private OpenSSL.BigNumber a;
		private uint8[] a_public;

		public EscrowSrpSession () {
			var ctx = new OpenSSL.BigNumberContext.secure ();
			n = new OpenSSL.BigNumber.from_big_endian (decode_hex (N_HEX));
			g = new OpenSSL.BigNumber.from_big_endian ({ 2 });

			var secret = new uint8[32];
			OpenSSL.Rng.generate (secret);
			a = new OpenSSL.BigNumber.from_big_endian (secret);

			var a_pub = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mod_exp (a_pub, g, a, n, ctx);
			a_public = trim (a_pub);
		}

		/**
		 * The client ephemeral A, minimal big-endian, as sent in SRP_INIT and hashed into the proofs.
		 */
		public uint8[] public_a () {
			return a_public;
		}

		/**
		 * Complete the handshake against the server's challenge (its ephemeral B and the salt),
		 * deriving the shared session key K and the client proof M1. The username is the account's
		 * numeric DSID (as the escrow proxy returns it), the password the escrow secret.
		 */
		public void process (uint8[] username, uint8[] password, uint8[] salt, uint8[] server_public)
				throws Efni.Error {
			var ctx = new OpenSSL.BigNumberContext.secure ();
			var b_pub = new OpenSSL.BigNumber.from_big_endian (server_public);
			uint8[] b_trimmed = trim (b_pub);

			uint8[] pad_n = pad (n);
			uint8[] pad_g = pad (g);
			var k = new OpenSSL.BigNumber.from_big_endian (sha256 (cat (pad_n, pad_g)));

			var x = new OpenSSL.BigNumber.from_big_endian (
				sha256 (cat (salt, sha256 (cat (username, ":".data, password)))));

			var u = new OpenSSL.BigNumber.from_big_endian (sha256 (cat (a_public, b_trimmed)));

			// base = (B - k * g^x) mod N
			var gx = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mod_exp (gx, g, x, n, ctx);
			var kgx = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mul (kgx, k, gx, ctx);
			OpenSSL.BigNumber.mod_nonneg (kgx, kgx, n, ctx);
			var base_value = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.sub (base_value, b_pub, kgx);
			OpenSSL.BigNumber.mod_nonneg (base_value, base_value, n, ctx);

			// exponent = a + u * x
			var ux = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mul (ux, u, x, ctx);
			var exponent = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.add (exponent, a, ux);

			// S = base^exponent mod N
			var s = new OpenSSL.BigNumber ();
			OpenSSL.BigNumber.mod_exp (s, base_value, exponent, n, ctx);
			shared_key = sha256 (trim (s));

			uint8[] h_n = sha256 (pad_n);
			uint8[] h_g = sha256 (pad_g);
			var h_xor = new uint8[32];
			for (int i = 0; i != 32; i++)
				h_xor[i] = h_n[i] ^ h_g[i];
			client_proof = sha256 (cat (h_xor, sha256 (username), salt, a_public, b_trimmed, shared_key));
		}

		/**
		 * The server proof M2 = H(A || M1 || K) idun must see echoed back before it trusts, and
		 * decrypts, the recovered record.
		 */
		public uint8[] server_proof () {
			return sha256 (cat (a_public, client_proof, shared_key));
		}

		private uint8[] pad (OpenSSL.BigNumber value) {
			var buffer = new uint8[N_LENGTH];
			value.to_big_endian_padded (buffer);
			return buffer;
		}

		private static uint8[] trim (OpenSSL.BigNumber value) {
			int n_bytes = value.num_bytes ();
			if (n_bytes == 0)
				return new uint8[] { 0 };
			var buffer = new uint8[n_bytes];
			value.to_big_endian (buffer);
			return buffer;
		}

		private static uint8[] sha256 (uint8[] data) {
			var checksum = new Checksum (ChecksumType.SHA256);
			checksum.update (data, data.length);
			var digest = new uint8[32];
			size_t length = digest.length;
			checksum.get_digest (digest, ref length);
			return digest;
		}

		private static uint8[] cat (uint8[] a, uint8[]? b = null, uint8[]? c = null,
				uint8[]? d = null, uint8[]? e = null, uint8[]? f = null) {
			var buffer = new ByteArray ();
			buffer.append (a);
			if (b != null) buffer.append (b);
			if (c != null) buffer.append (c);
			if (d != null) buffer.append (d);
			if (e != null) buffer.append (e);
			if (f != null) buffer.append (f);
			return buffer.data;
		}

		private static uint8[] decode_hex (string hex) {
			var bytes = new uint8[hex.length / 2];
			for (int i = 0; i != bytes.length; i++)
				bytes[i] = (uint8) hex.substring (i * 2, 2).to_long (null, 16);
			return bytes;
		}
	}

	/**
	 * The escrow proxy frames its SRP blobs as a key-vault message: a fixed-size header, a table
	 * of section offsets, and length-prefixed sections. Idun both parses the server's challenge
	 * and recovery blobs and builds the proof blob it sends back.
	 */
	public sealed class EscrowKeyVault {
		private uint8[] header;
		private GenericArray<Bytes> sections = new GenericArray<Bytes> ();

		public EscrowKeyVault (uint8[] header) {
			this.header = header;
		}

		/**
		 * Parse a packed message into its header and the requested number of sections.
		 */
		public static Bytes[] unpack (uint8[] data, int header_length, int section_count,
				out uint8[] header) throws Efni.Error {
			if (data.length < 4 + header_length)
				throw new Efni.Error.PROTOCOL ("Truncated escrow key-vault message");
			header = data[4 : 4 + header_length];

			int table = 4 + header_length;
			int body = table + (section_count + 1) * 4;
			var result = new Bytes[section_count];
			for (int i = 0; i != section_count; i++) {
				int offset = (int) read_be32 (data, table + i * 4);
				int start = body + offset;
				if (start + 4 > data.length)
					throw new Efni.Error.PROTOCOL ("Corrupt escrow key-vault section offset");
				int size = (int) read_be32 (data, start);
				if (start + 4 + size > data.length)
					throw new Efni.Error.PROTOCOL ("Corrupt escrow key-vault section length");
				result[i] = new Bytes (data[start + 4 : start + 4 + size]);
			}
			return result;
		}

		/**
		 * Append a length-prefixed section.
		 */
		public void add_section (uint8[] data) {
			sections.add (new Bytes (prefixed (data)));
		}

		/**
		 * Append a length-prefixed section zero-padded to a fixed on-wire size.
		 */
		public void add_section_padded (uint8[] data, int size) throws Efni.Error {
			uint8[] framed = prefixed (data);
			if (framed.length > size)
				throw new Efni.Error.PROTOCOL ("Escrow key-vault section exceeds its fixed size");
			var padded = new uint8[size];
			Memory.copy (padded, framed, framed.length);
			sections.add (new Bytes (padded));
		}

		/**
		 * Serialize the message: total length, header, the offset table (one entry per section plus
		 * the trailing body length), and the section bodies.
		 */
		public uint8[] pack () {
			var body = new ByteArray ();
			var offsets = new int[sections.length + 1];
			for (int i = 0; i != sections.length; i++) {
				offsets[i] = (int) body.len;
				body.append (sections[i].get_data ());
			}
			offsets[sections.length] = (int) body.len;

			var result = new ByteArray ();
			result.append ({ 0, 0, 0, 0 });
			result.append (header);
			foreach (int offset in offsets)
				result.append (be32 (offset));
			result.append (body.data);

			uint8[] total = be32 ((int) result.len);
			for (int i = 0; i != 4; i++)
				result.data[i] = total[i];
			return result.data;
		}

		private static uint8[] prefixed (uint8[] data) {
			var framed = new uint8[4 + data.length];
			uint8[] length = be32 (data.length);
			Memory.copy (framed, length, 4);
			Memory.copy ((uint8 *) framed + 4, data, data.length);
			return framed;
		}

		public static uint32 read_be32 (uint8[] data, int offset) {
			return ((uint32) data[offset] << 24) | ((uint32) data[offset + 1] << 16) |
				((uint32) data[offset + 2] << 8) | (uint32) data[offset + 3];
		}

		private static uint8[] be32 (int value) {
			return new uint8[] {
				(uint8) ((value >> 24) & 0xff), (uint8) ((value >> 16) & 0xff),
				(uint8) ((value >> 8) & 0xff), (uint8) (value & 0xff)
			};
		}
	}
}
