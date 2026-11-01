using Efni;

namespace Idun {
	/**
	 * Decrypts a CKKS zone's keychain items with the account's recovered top-level keys. CKKS wraps
	 * each zone under a TLK: the class keys (classA, classC) are AES-SIV-wrapped under the TLK, and
	 * each item's per-item key is AES-SIV-wrapped under its class key, with the item body itself
	 * AES-SIV-sealed under the per-item key and authenticated by the item's metadata. Given the
	 * TLKs recovered from escrow, this walks that hierarchy and returns the decrypted item
	 * attribute dictionaries — where the account's Key Transparency signing key lives.
	 */
	public sealed class CkksKeychain : Object {
		private const string[] AAD_EXCLUDED = {
			"gen", "pcspublickey", "UUID", "data", "pcsservice", "pcspublicidentity",
			"parentkeyref", "uploadver", "wrappedkey", "encver"
		};

		/**
		 * Decrypt every item in a zone that unwraps under the supplied TLKs (keyed by TLK uuid).
		 * Items that fail to decrypt — a missing key, an unsupported field type in the
		 * authenticated data — are skipped so the rest still come through.
		 */
		public static Gee.List<DecryptedKeychainItem> decrypt_zone (Gee.List<CloudKitRecord> records,
				Gee.Map<string, Bytes> tlks) {
			var class_keys = new Gee.HashMap<string, Bytes> ();
			foreach (var record in records) {
				if (record.record_type != "synckey")
					continue;
				try {
					resolve_class_key (record, tlks, class_keys);
				} catch (GLib.Error e) {
				}
			}

			var items = new Gee.ArrayList<DecryptedKeychainItem> ();
			foreach (var record in records) {
				if (record.record_type != "item")
					continue;
				try {
					var attributes = decrypt_item (record, class_keys);
					if (attributes != null)
						items.add (new DecryptedKeychainItem (record.record_name, attributes, record));
				} catch (GLib.Error e) {
				}
			}
			return items;
		}

		private static void resolve_class_key (CloudKitRecord synckey, Gee.Map<string, Bytes> tlks,
				Gee.Map<string, Bytes> class_keys) throws Efni.Error {
			string cls = synckey.string_field ("class") ?? "";
			if (cls == "tlk") {
				if (tlks.has_key (synckey.record_name))
					class_keys[synckey.record_name] = tlks[synckey.record_name];
				return;
			}
			string parent = synckey.string_field ("parentkeyref") ?? "";
			Bytes? tlk = tlks.has_key (parent) ? tlks[parent]
				: (class_keys.has_key (parent) ? class_keys[parent] : null);
			string? wrapped = synckey.string_field ("wrappedkey");
			if (tlk == null || wrapped == null)
				return;
			uint8[] key = OctagonCrypto.aes_siv_decrypt (tlk.get_data (), Base64.decode (wrapped),
				new Bytes[] {});
			class_keys[synckey.record_name] = new Bytes (key);
		}

		private static Plist? decrypt_item (CloudKitRecord item, Gee.Map<string, Bytes> class_keys)
				throws Efni.Error {
			string parent = item.string_field ("parentkeyref") ?? "";
			if (!class_keys.has_key (parent))
				return null;
			string? wrapped = item.string_field ("wrappedkey");
			Bytes? data = item.bytes_field ("data");
			if (wrapped == null || data == null || data.length < 16)
				return null;

			uint8[] item_key = OctagonCrypto.aes_siv_decrypt (class_keys[parent].get_data (),
				Base64.decode (wrapped), new Bytes[] {});

			uint8[] all = data.get_data ();
			uint8[] nonce = all[0 : 16];
			uint8[] body = all[16 : all.length];
			uint8[] plaintext = OctagonCrypto.aes_siv_decrypt (item_key, body,
				build_item_aad (item, nonce));
			plaintext = strip_iso7816_padding (plaintext);

			try {
				return new Plist.from_data (plaintext);
			} catch (PlistError e) {
				return null;
			}
		}

		private static Bytes[] build_item_aad (CloudKitRecord item, uint8[] nonce) {
			var map = new Gee.TreeMap<string, Bytes> ();
			map["UUID"] = new Bytes (item.record_name.data);
			map["encver"] = le8 (item.has_int_field ("encver") ? item.int_field ("encver") : 2);
			map["gen"] = le8 (item.has_int_field ("gen") ? item.int_field ("gen") : 0);
			map["wrappedkey"] = new Bytes ((item.string_field ("parentkeyref") ?? "").data);

			if (item.has_int_field ("pcsservice"))
				map["pcsservice"] = le8 (item.int_field ("pcsservice"));
			foreach (string pcs in new string[] { "pcspublicidentity", "pcspublickey" }) {
				var value = item.bytes_field (pcs);
				if (value != null)
					map[pcs] = value;
			}

			foreach (string name in item.field_names ()) {
				if (name.has_prefix ("server_") || is_aad_excluded (name) || map.has_key (name))
					continue;
				if (item.has_int_field (name))
					map[name] = le8 (item.int_field (name));
				else if (item.string_field (name) != null)
					map[name] = new Bytes (item.string_field (name).data);
				else if (item.bytes_field (name) != null)
					map[name] = item.bytes_field (name);
			}

			var aad = new Gee.ArrayList<Bytes> ();
			aad.add (new Bytes (nonce));
			foreach (var entry in map.entries)
				aad.add (entry.value);
			return aad.to_array ();
		}

		private static bool is_aad_excluded (string name) {
			foreach (string excluded in AAD_EXCLUDED) {
				if (excluded == name)
					return true;
			}
			return false;
		}

		private static Bytes le8 (int64 value) {
			var bytes = new uint8[8];
			uint64 v = (uint64) value;
			for (int i = 0; i != 8; i++)
				bytes[i] = (uint8) (v >> (8 * i));
			return new Bytes (bytes);
		}

		private static uint8[] strip_iso7816_padding (uint8[] data) {
			int i = data.length - 1;
			while (i >= 0 && data[i] == 0x00)
				i--;
			if (i >= 0 && data[i] == 0x80)
				return data[0 : i];
			return data;
		}
	}

	/**
	 * A decrypted keychain item: the CKKS record name and the item's attribute dictionary (its
	 * class, access group, service, account, and the secret in v_Data).
	 */
	public sealed class DecryptedKeychainItem : Object {
		public string record_name {
			get;
			construct;
		}

		public Plist attributes {
			get;
			construct;
		}

		public CloudKitRecord record {
			get;
			construct;
		}

		public DecryptedKeychainItem (string record_name, Plist attributes, CloudKitRecord record) {
			Object (record_name: record_name, attributes: attributes, record: record);
		}
	}
}
