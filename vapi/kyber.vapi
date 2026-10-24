[CCode (cheader_filename = "api.h")]
namespace Kyber {
	[CCode (cname = "pqcrystals_kyber1024_ref_PUBLICKEYBYTES")]
	public const int PUBLIC_KEY_BYTES;
	[CCode (cname = "pqcrystals_kyber1024_ref_SECRETKEYBYTES")]
	public const int SECRET_KEY_BYTES;
	[CCode (cname = "pqcrystals_kyber1024_ref_CIPHERTEXTBYTES")]
	public const int CIPHERTEXT_BYTES;
	[CCode (cname = "pqcrystals_kyber1024_ref_BYTES")]
	public const int SHARED_SECRET_BYTES;

	[CCode (cname = "pqcrystals_kyber1024_ref_keypair")]
	public int keypair ([CCode (array_length = false)] uint8[] pk, [CCode (array_length = false)] uint8[] sk);
	[CCode (cname = "pqcrystals_kyber1024_ref_enc")]
	public int enc ([CCode (array_length = false)] uint8[] ct, [CCode (array_length = false)] uint8[] ss,
		[CCode (array_length = false)] uint8[] pk);
	[CCode (cname = "pqcrystals_kyber1024_ref_dec")]
	public int dec ([CCode (array_length = false)] uint8[] ss, [CCode (array_length = false)] uint8[] ct,
		[CCode (array_length = false)] uint8[] sk);
}
