using Efni;

namespace Idun {
	public sealed class CoreProfileService : Object, AsyncInitable {
		public signal void stackshot (Bytes blob);
		public signal void kperfdata (Bytes blob);

		public ChannelProvider channel_provider {
			get;
			construct;
		}

		private DTXChannel channel;

		private CoreProfileService (ChannelProvider channel_provider) {
			Object (channel_provider: channel_provider);
		}

		public static async CoreProfileService open (ChannelProvider channel_provider, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			var service = new CoreProfileService (channel_provider);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Efni.Error, IOError {
			var connection = yield DTXConnection.obtain (channel_provider, cancellable);

			channel = connection.make_channel ("com.apple.instruments.server.services.coreprofilesessiontap");
			channel.notification.connect (on_notification);
			channel.data.connect (on_data);

			return true;
		}

		public async void set_config (KtraceConfig config, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var args = new DTXArgumentListBuilder ()
				.append_object (config.encode ());
			yield channel.invoke ("setConfig:", args, cancellable);
		}

		public async void start (Cancellable? cancellable = null) throws Efni.Error, IOError {
			yield channel.invoke ("start", null, cancellable);
		}

		public async void stop (Cancellable? cancellable = null) throws Efni.Error, IOError {
			yield channel.invoke ("stop", null, cancellable);
		}

		private void on_notification (NSObject obj) {
			// printerr ("on_notification(): %s\n", obj.to_string ());
		}

		private void on_data (Bytes blob) {
			if (Kcdata.is_stackshot (blob))
				stackshot (blob);
			else
				kperfdata (blob);
		}
	}

	public abstract class TapConfig : Object {
		public TapRecordingMode buffer_mode {
			get {
				return _buffer_mode;
			}
			set {
				_buffer_mode = value;
				if (value != POLLED)
					_polling_interval = 0;
			}
		}

		public uint64 polling_interval {
			get;
			set;
			default = 500;
		}

		public uint64 window_size {
			get;
			set;
			default = 0;
		}

		public bool spool_to_disk_when_possible {
			get;
			set;
			default = false;
		}

		public bool discard_heartbeats_when_possible {
			get;
			set;
			default = false;
		}

		private TapRecordingMode _buffer_mode = POLLED;

		internal virtual NSDictionary encode () {
			var dict = new NSDictionary ();

			dict.set_value ("bm", new NSNumber.from_integer (_buffer_mode));

			if (_polling_interval != 0)
				dict.set_value ("ur", new NSNumber.from_integer ((int64) _polling_interval));

			if (_window_size != 0)
				dict.set_value ("ws", new NSNumber.from_integer ((int64) _window_size));

			if (_spool_to_disk_when_possible)
				dict.set_value ("s2d", new NSNumber.from_boolean (true));

			if (_discard_heartbeats_when_possible)
				dict.set_value ("nohb", new NSNumber.from_boolean (true));

			return dict;
		}
	}

	public enum TapRecordingMode {
		POLLED,
		IMMEDIATE,
		WINDOWED,
	}

	public sealed class KtraceConfig : TapConfig {
		public bool can_use_raw_ktrace_file {
			get;
			set;
			default = false;
		}

		public KtraceRecordingPriority recording_priority {
			get;
			set;
			default = FOREGROUND;
		}

		public uint collection_interval {
			get;
			set;
			default = 0;
		}

		public uint64 buffer_size_override {
			get;
			set;
			default = 0;
		}

		public uint64 buffer_size_override_clamping {
			get;
			set;
			default = 0;
		}

		public NSDictionary? provider_options {
			get;
			set;
			default = null;
		}

		private Gee.List<KtraceTapTriggerConfig> trigger_configs = new Gee.ArrayList<KtraceTapTriggerConfig> ();

		public void add_trigger_config (KtraceTapTriggerConfig tc) {
			trigger_configs.add (tc);
		}

		internal override NSDictionary encode () {
			var dict = base.encode ();

			if (can_use_raw_ktrace_file)
				dict.set_value ("curkt", new NSNumber.from_boolean (true));

			dict.set_value ("rp", new NSNumber.from_integer (_recording_priority));

			if (_collection_interval != 0)
				dict.set_value ("kco", new NSNumber.from_integer (_collection_interval));

			if (_buffer_size_override != 0)
				dict.set_value ("bso", new NSNumber.from_integer ((int64) _buffer_size_override));

			if (_buffer_size_override_clamping != 0)
				dict.set_value ("bsoc", new NSNumber.from_integer ((int64) _buffer_size_override_clamping));

			if (_provider_options != null)
				dict.set_value ("po", _provider_options);

			var tc = new NSArray ();
			foreach (var cfg in trigger_configs)
				tc.add_object (cfg.encode ());
			dict.set_value ("tc", tc);

			return dict;
		}
	}

	public enum KtraceRecordingPriority {
		BACKGROUND = 10,
		FOREGROUND = 100,
	}

	public sealed class KtraceTapTriggerConfig : Object {
		public KtraceTapTriggerKind kind {
			get;
			construct;
		}

		public KdebugCodeSet? filter {
			get;
			set;
		}

		public bool is_all_processes {
			get {
				return included_pids == null;
			}
			set {
				if (value)
					included_pids = null;
				else
					ensure_included_pids ();
			}
		}

		public uint callstack_frame_depth {
			get;
			set;
			default = 0;
		}

		public KtraceTapActions actions {
			get;
			default = new KtraceTapActions ();
		}

		private Gee.Set<uint>? included_pids = null;

		public KtraceTapTriggerConfig (KtraceTapTriggerKind kind) {
			Object (kind: kind);
		}

		public void include_pid (uint pid) {
			ensure_included_pids ().add (pid);
		}

		private unowned Gee.Set<uint> ensure_included_pids () {
			if (included_pids == null)
				included_pids = new Gee.HashSet<uint> ();
			return included_pids;
		}

		internal NSDictionary encode () {
			var dict = new NSDictionary ();

			dict.set_value ("uuid", new NSString (Uuid.string_random ().up ()));

			dict.set_value ("tk", new NSNumber.from_integer (_kind));

			if (_filter != null) {
				dict.set_value ("kdf", new NSString (_filter.legacy_xml));
				dict.set_value ("kdf2", _filter.kdebug_codes);
			}

			if (included_pids != null) {
				var pf = new NSArray ();
				foreach (var pid in included_pids)
					pf.add_object (new NSNumber.from_integer (pid));
				dict.set_value ("pf", pf);
			}

			if (_callstack_frame_depth != 0)
				dict.set_value ("csd", new NSNumber.from_integer (_callstack_frame_depth));

			var actions = _actions.items;
			if (!actions.is_empty) {
				var arr = new NSArray ();
				foreach (var action in actions)
					arr.add_object (action.encode ());
				dict.set_value ("ta", arr);
			}

			return dict;
		}
	}

	public enum KtraceTapTriggerKind {
		TIME = 1,
		PMI,
		KDEBUG,
	}

	public sealed class KtraceTapActions : Object {
		internal Gee.List<KtraceTapAction> items = new Gee.ArrayList<KtraceTapAction> ();

		public unowned KtraceTapActions add (KtraceTapAction action) {
			items.add (action);
			return this;
		}

		public unowned KtraceTapActions add_stack_collection (KtraceTapStackCollectionMode mode) {
			items.add (new KtraceTapStackCollectionAction (mode));
			return this;
		}

		public unowned KtraceTapActions add_baseline () {
			items.add (new KtraceTapAction0 ());
			items.add (new KtraceTapAction2 ());
			return this;
		}

		public unowned KtraceTapActions add_pmc_event (string event_name, string counter_name, uint32 extra = 0) {
			items.add (new KtraceTapAddPmcEventAction (event_name, counter_name, extra));
			return this;
		}

		public unowned KtraceTapActions add_kdebug_codeset (KdebugCodeSet codeset) {
			items.add (new KtraceTapAddKdebugCodeSetAction (codeset.kdebug_codes));
			return this;
		}

		public unowned KtraceTapActions add_kdebug_legacy_backtrace_filter () {
			items.add (new KtraceTapKdebugBacktraceFilterAction ());
			return this;
		}
	}

	public enum KtraceTapActionKind {
		ACTION0,
		STACK_COLLECTION,
		ACTION2,
		KDEBUG_BACKTRACE_FILTER,
		ADD_PMC_EVENT,
		ADD_KDEBUG_CODESET,
	}

	public abstract class KtraceTapAction : Object {
		public abstract KtraceTapActionKind kind {
			get;
		}

		internal abstract NSArray encode ();
	}

	public sealed class KtraceTapAction0 : KtraceTapAction {
		public override KtraceTapActionKind kind {
			get {
				return ACTION0;
			}
		}

		internal override NSArray encode () {
			var a = new NSArray ();
			a.add_object (new NSNumber.from_integer (kind));
			return a;
		}
	}

	public sealed class KtraceTapAction2 : KtraceTapAction {
		public override KtraceTapActionKind kind {
			get {
				return ACTION2;
			}
		}

		internal override NSArray encode () {
			var a = new NSArray ();
			a.add_object (new NSNumber.from_integer (kind));
			return a;
		}
	}

	public sealed class KtraceTapStackCollectionAction : KtraceTapAction {
		public KtraceTapStackCollectionMode mode {
			get {
				return _mode;
			}
			set {
				_mode = value;
			}
		}

		private KtraceTapStackCollectionMode _mode;

		public KtraceTapStackCollectionAction (KtraceTapStackCollectionMode mode) {
			_mode = mode;
		}

		public override KtraceTapActionKind kind {
			get {
				return STACK_COLLECTION;
			}
		}

		internal override NSArray encode () {
			var a = new NSArray ();
			a.add_object (new NSNumber.from_integer (kind));
			a.add_object (new NSNumber.from_boolean ((_mode & KtraceTapStackCollectionMode.USER) != 0));
			a.add_object (new NSNumber.from_boolean ((_mode & KtraceTapStackCollectionMode.KERNEL) != 0));
			return a;
		}
	}

	[Flags]
	public enum KtraceTapStackCollectionMode {
		NONE   = 0,
		USER   = (1 << 0),
		KERNEL = (1 << 1),
	}

	public sealed class KtraceTapKdebugBacktraceFilterAction : KtraceTapAction {
		public override KtraceTapActionKind kind {
			get {
				return KDEBUG_BACKTRACE_FILTER;
			}
		}

		internal override NSArray encode () {
			var a = new NSArray ();
			a.add_object (new NSNumber.from_integer (kind));
			return a;
		}
	}

	public sealed class KtraceTapAddPmcEventAction : KtraceTapAction {
		public string event_name {
			get {
				return _event_name;
			}
			set {
				_event_name = value;
			}
		}

		public string counter_name {
			get {
				return _counter_name;
			}
			set {
				_counter_name = value;
			}
		}

		public uint32 extra {
			get {
				return _extra;
			}
			set {
				_extra = value;
			}
		}

		private string _event_name;
		private string _counter_name;
		private uint32 _extra;

		public KtraceTapAddPmcEventAction (string event_name, string counter_name, uint32 extra = 0) {
			_event_name = event_name;
			_counter_name = counter_name;
			_extra = extra;
		}

		public override KtraceTapActionKind kind {
			get {
				return ADD_PMC_EVENT;
			}
		}

		internal override NSArray encode () {
			var a = new NSArray ();
			a.add_object (new NSNumber.from_integer (kind));
			a.add_object (new NSString (_event_name));
			a.add_object (new NSString (_counter_name));
			a.add_object (new NSNumber.from_integer (_extra));
			return a;
		}
	}

	public sealed class KtraceTapAddKdebugCodeSetAction : KtraceTapAction {
		public NSSet codes {
			get {
				return _codes;
			}
			set {
				_codes = value;
			}
		}

		private NSSet _codes;

		public KtraceTapAddKdebugCodeSetAction (NSSet codes) {
			_codes = codes;
		}

		public override KtraceTapActionKind kind {
			get {
				return ADD_KDEBUG_CODESET;
			}
		}

		internal override NSArray encode () {
			var a = new NSArray ();
			a.add_object (new NSNumber.from_integer (kind));
			a.add_object (_codes);
			return a;
		}
	}

	public sealed class KdebugCodeSet : Object {
		public string legacy_xml {
			owned get {
				var xml = new StringBuilder.sized (256);
				xml.append ("<events>");

				foreach (var c in codes) {
					var kc = KdebugCode (c);

					xml.append ("<event type=\"KDebug\" class=\"");

					var klass = kc.klass;
					if (klass == ANY)
						xml.append_c ('*');
					else
						xml.append_printf ("%u", klass);

					xml.append ("\" subclass=\"");

					var subclass = kc.subclass;
					if (subclass == KDEBUG_SUBCLASS_ANY)
						xml.append_c ('*');
					else
						xml.append_printf ("%u", subclass);

					xml.append ("\" code=\"");

					uint code = kc.code;
					if (code == KDEBUG_CODE_ANY)
						xml.append_c ('*');
					else
						xml.append_printf ("%u", code);

					xml.append ("\"/>");
				}

				xml.append ("</events>");

				return xml.str;
			}
		}

		public NSSet kdebug_codes {
			get {
				if (_kdebug_codes == null) {
					_kdebug_codes = new NSSet ();
					foreach (var c in codes)
						_kdebug_codes.add_object (new NSNumber.from_integer (c));
				}
				return _kdebug_codes;
			}
		}

		private Gee.Set<uint> codes = new Gee.HashSet<uint> ();
		private NSSet _kdebug_codes = null;

		public KdebugCodeSet copy () {
			var s = new KdebugCodeSet ();
			s.codes.add_all (codes);
			s._kdebug_codes = _kdebug_codes;
			return s;
		}

		public unowned KdebugCodeSet add (KdebugCode code) {
			codes.add (code.raw);
			_kdebug_codes = null;
			return this;
		}
	}
}
