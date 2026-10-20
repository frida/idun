using Efni;

namespace Idun {
	public sealed class PasteboardService : Object {
		public signal void changed (PasteboardSnapshot snapshot);
		public signal void closed (Efni.Error? error);

		private XpcConnection connection;

		private const string PASTEBOARD_NAME = "general";

		public static async PasteboardService open (Device device, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var channel = yield device.open_tcp_channel ("com.apple.coredevice.pasteboardservice", ALLOW_TUNNEL, cancellable);
			return new PasteboardService (channel.stream);
		}

		private PasteboardService (IOStream stream) {
			connection = new XpcConnection (stream);
			connection.close.connect (on_close);
			connection.message.connect (on_message);
			connection.activate ();
		}

		public void close () {
			connection.cancel ();
		}

		public async PasteboardSnapshot pull (Cancellable? cancellable = null) throws Efni.Error, IOError {
			Bytes request = new XpcBodyBuilder ()
				.begin_dictionary ()
					.set_member_name ("command")
					.add_string_value ("PULL")
					.set_member_name ("pasteboardName")
					.add_string_value (PASTEBOARD_NAME)
					.set_member_name ("dataPolicy")
					.begin_dictionary ()
						.set_member_name ("allResolved")
						.begin_dictionary ()
						.end_dictionary ()
					.end_dictionary ()
				.end_dictionary ()
				.build ();
			XpcMessage reply = yield connection.request (request, cancellable);

			return PasteboardSnapshot.parse (new VariantReader (reply.body));
		}

		public async void set_text (string text, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var item = new PasteboardItem ();
			item.representations[PasteboardItem.TEXT_TYPE] = new Bytes (text.data);

			yield set_items (new Gee.ArrayList<PasteboardItem>.wrap ({ item }), cancellable);
		}

		public async void set_items (Gee.List<PasteboardItem> items, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var request = new XpcBodyBuilder ()
				.begin_dictionary ()
					.set_member_name ("command")
					.add_string_value ("SET")
					.set_member_name ("pasteboardName")
					.add_string_value (PASTEBOARD_NAME)
					.set_member_name ("items")
					.begin_array ();
			foreach (PasteboardItem item in items) {
				request
					.begin_dictionary ()
						.set_member_name ("types")
						.begin_array ();
				foreach (string type in item.representations.keys)
					request.add_string_value (type);
				request
						.end_array ()
						.set_member_name ("data")
						.begin_dictionary ();
				foreach (var representation in item.representations.entries) {
					request
						.set_member_name (representation.key)
						.begin_dictionary ()
							.set_member_name ("data")
							.add_data_value (representation.value)
						.end_dictionary ();
				}
				request
						.end_dictionary ()
					.end_dictionary ();
			}
			request
					.end_array ()
				.end_dictionary ();

			yield connection.request (request.build (), cancellable);
		}

		public async void enable_notifications (Cancellable? cancellable = null) throws Efni.Error, IOError {
			Bytes request = new XpcBodyBuilder ()
				.begin_dictionary ()
					.set_member_name ("command")
					.add_string_value ("AUTONOTIFY")
					.set_member_name ("pasteboardName")
					.add_string_value (PASTEBOARD_NAME)
					.set_member_name ("enable")
					.add_bool_value (true)
				.end_dictionary ()
				.build ();
			yield connection.request (request, cancellable);
		}

		private void on_close (Efni.Error? error) {
			closed (error);
		}

		private void on_message (XpcMessage msg) {
			if (msg.body == null)
				return;

			var reader = new VariantReader (msg.body);
			try {
				if (reader.read_member ("command").get_string_value () != "PUSH")
					return;
				reader.end_member ();

				changed (PasteboardSnapshot.parse (reader));
			} catch (Efni.Error e) {
			}
		}
	}

	public sealed class PasteboardSnapshot : Object {
		public int64 change_count {
			get;
			set;
		}

		public Gee.List<PasteboardItem> items {
			get;
			default = new Gee.ArrayList<PasteboardItem> ();
		}

		public string? text {
			owned get {
				foreach (PasteboardItem item in items) {
					Bytes? data = item.representations[PasteboardItem.TEXT_TYPE];
					if (data != null)
						return (string) data.get_data ();
				}
				return null;
			}
		}

		internal static PasteboardSnapshot parse (VariantReader reader) throws Efni.Error {
			var snapshot = new PasteboardSnapshot ();

			reader.read_member ("pasteboard");

			snapshot.change_count = reader
				.read_member ("metadata")
				.read_member ("changeCount")
				.get_int64_value ();
			reader.end_member ().end_member ();

			reader.read_member ("items");
			uint n = reader.count_elements ();
			for (uint i = 0; i != n; i++) {
				reader.read_element (i);
				snapshot.items.add (PasteboardItem.parse (reader));
				reader.end_element ();
			}
			reader.end_member ();

			reader.end_member ();

			return snapshot;
		}
	}

	public sealed class PasteboardItem : Object {
		public const string TEXT_TYPE = "public.utf8-plain-text";

		public Gee.Map<string, Bytes> representations {
			get;
			default = new Gee.HashMap<string, Bytes> ();
		}

		internal static PasteboardItem parse (VariantReader reader) throws Efni.Error {
			var item = new PasteboardItem ();

			reader.read_member ("data");
			foreach (string type in reader.list_members ()) {
				item.representations[type] = reader
					.read_member (type)
					.read_member ("data")
					.get_data_value ();
				reader.end_member ().end_member ();
			}
			reader.end_member ();

			return item;
		}
	}
}
