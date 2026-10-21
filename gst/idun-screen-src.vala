namespace Idun {
	public class ScreenSrc : Gst.Bin {
		public DisplayStream? stream {
			get {
				return _stream;
			}
			set {
				_stream = value;
			}
		}

		public string? udid {
			get;
			set;
		}

		private DisplayStream? _stream;

		private Gst.GhostPad src_pad;
		private Gst.App.Src rtp_src;
		private Gst.App.Src rtcp_src;
		private Gst.App.Sink rtcp_sink;
		private Gst.Element session;
		private Gst.Element depayloader;
		private Gst.Element output;
		private ulong rtp_handler;
		private ulong rtcp_handler;
		private ulong codec_data_handler;
		private ulong started_handler;

		private Thread<void>? worker;
		private MainContext? worker_context;
		private MainLoop? worker_loop;
		private DeviceMonitor? monitor;
		private Cancellable? io_cancellable;
		private bool opening = false;
		private SourceFunc? open_wait;

		private const int RTP_PROFILE_AVPF = 3;

		class construct {
			add_pad_template (new Gst.PadTemplate ("src", SRC, ALWAYS, new Gst.Caps.empty_simple ("video/x-h264")));
			set_static_metadata ("Idun screen source", "Source/Video",
				"Receives a CoreDevice display stream as H.264",
				"Ole André Vadla Ravnås <oleavr@frida.re>");
		}

		construct {
			src_pad = new Gst.GhostPad.no_target_from_template ("src", get_pad_template ("src"));
			add_pad (src_pad);

			rtp_src = (Gst.App.Src) Gst.ElementFactory.make ("appsrc", "rtp_src");
			rtcp_src = (Gst.App.Src) Gst.ElementFactory.make ("appsrc", "rtcp_src");
			rtcp_sink = (Gst.App.Sink) Gst.ElementFactory.make ("appsink", "rtcp_sink");
			session = Gst.ElementFactory.make ("rtpbin", "session");
			depayloader = Gst.ElementFactory.make ("rtph264depay", "depayloader");
			output = Gst.ElementFactory.make ("queue", "output");

			rtp_src.set ("is-live", true, "format", Gst.Format.TIME, "do-timestamp", true);
			rtcp_src.caps = new Gst.Caps.empty_simple ("application/x-rtcp");
			rtcp_src.set ("is-live", true);
			rtcp_sink.set ("emit-signals", true, "sync", false, "async", false);
			depayloader.set ("request-keyframe", true, "wait-for-keyframe", true);
			session.set ("rtp-profile", RTP_PROFILE_AVPF);

			add_many (rtp_src, rtcp_src, rtcp_sink, session, depayloader, output);

			rtp_src.link_pads ("src", session, "recv_rtp_sink_0");
			rtcp_src.link_pads ("src", session, "recv_rtcp_sink_0");
			session.link_pads ("send_rtcp_src_0", rtcp_sink, "sink");
			depayloader.link (output);

			GLib.Signal.connect (session, "request-pt-map", (GLib.Callback) on_request_pt_map, this);
			session.pad_added.connect (on_rtp_pad_added);
			rtcp_sink.new_sample.connect (on_rtcp_ready);

			src_pad.set_target (output.get_static_pad ("src"));
		}

		public override Gst.StateChangeReturn change_state (Gst.StateChange transition) {
			if (transition == NULL_TO_READY)
				start_worker ();

			Gst.StateChangeReturn result = base.change_state (transition);

			if (transition == READY_TO_NULL)
				stop_worker ();

			return result;
		}

		private void start_worker () {
			worker_context = new MainContext ();
			worker_loop = new MainLoop (worker_context);
			io_cancellable = new Cancellable ();
			worker = new Thread<void> ("idun-screen-src", run_worker);
		}

		private void run_worker () {
			worker_context.push_thread_default ();

			open_stream.begin ();
			worker_loop.run ();

			worker_context.pop_thread_default ();
		}

		private async void open_stream () {
			opening = true;

			try {
				if (_stream == null) {
					monitor = new DeviceMonitor ();
#if HAVE_DAEMON
					string? idund = Environment.get_variable ("IDUND");
					if (idund != null)
						monitor.set_daemon_locator (() => idund);
#endif

					string? wanted = udid;
					Device device = (wanted != null)
						? yield monitor.get_device_by_udid (wanted, -1, io_cancellable)
						: yield monitor.get_device (d => true, -1, io_cancellable);
					_stream = yield DisplayStream.open (device, io_cancellable);
				}

				attach_stream ();
				yield _stream.start (io_cancellable);
			} catch (GLib.Error e) {
				if (!(e is IOError.CANCELLED)) {
					message_full (ERROR, Gst.ResourceError.quark (), Gst.ResourceError.OPEN_READ,
						"Failed to open display stream: %s".printf (e.message), null,
						GLib.Log.FILE, GLib.Log.METHOD, GLib.Log.LINE);
				}
			}

			opening = false;

			if (open_wait != null) {
				var resume = (owned) open_wait;
				resume ();
			}
		}

		private void attach_stream () {
			rtp_handler = _stream.rtp.connect (on_rtp);
			rtcp_handler = _stream.rtcp.connect (on_rtcp);
			codec_data_handler = _stream.notify["codec-data"].connect (on_codec_data_changed);
			started_handler = _stream.started.connect (on_started);
		}

		private void on_started () {
			rtp_src.caps = describe_payload ();
		}

		private void stop_worker () {
			var source = new IdleSource ();
			source.set_callback (() => {
				teardown.begin ();
				return Source.REMOVE;
			});
			source.attach (worker_context);

			worker.join ();

			worker = null;
			worker_context = null;
			worker_loop = null;
			io_cancellable = null;
		}

		private async void teardown () {
			io_cancellable.cancel ();

			if (opening) {
				open_wait = teardown.callback;
				yield;
			}

			if (rtp_handler != 0)
				detach_stream ();

			if (monitor != null) {
				if (_stream != null) {
					try {
						yield _stream.close ();
					} catch (IOError e) {
					}
					_stream = null;
				}
				try {
					yield monitor.stop ();
				} catch (IOError e) {
				}
				monitor = null;
			}

			worker_loop.quit ();
		}

		private void detach_stream () {
			_stream.disconnect (rtp_handler);
			_stream.disconnect (rtcp_handler);
			_stream.disconnect (codec_data_handler);
			_stream.disconnect (started_handler);
			rtp_handler = 0;
		}

		private void on_rtp (Bytes data) {
			rtp_src.push_buffer (new Gst.Buffer.wrapped_bytes (data));
		}

		private void on_rtcp (Bytes data) {
			rtcp_src.push_buffer (new Gst.Buffer.wrapped_bytes (data));
		}

		private void on_codec_data_changed () {
			rtp_src.caps = describe_payload ();
		}

		private static Gst.Caps on_request_pt_map (Gst.Element session, uint session_id, uint pt, ScreenSrc self) {
			return self.describe_payload ();
		}

		private void on_rtp_pad_added (Gst.Pad pad) {
			if (!pad.name.has_prefix ("recv_rtp_src_"))
				return;
			pad.link (depayloader.get_static_pad ("sink"));
		}

		private Gst.FlowReturn on_rtcp_ready () {
			Gst.Sample sample = rtcp_sink.pull_sample ();
			Gst.Buffer buffer = sample.get_buffer ();

			Gst.MapInfo info;
			buffer.map (out info, READ);
			try {
				_stream.send_rtcp (new Bytes (info.data));
			} catch (GLib.Error e) {
			}
			buffer.unmap (info);

			return Gst.FlowReturn.OK;
		}

		private Gst.Caps describe_payload () {
			var caps = new Gst.Caps.simple ("application/x-rtp",
				"media", typeof (string), "video",
				"clock-rate", typeof (int), (int) _stream.clock_rate,
				"encoding-name", typeof (string), "H264",
				"payload", typeof (int), (int) _stream.payload_type,
				"ssrc", typeof (uint), _stream.remote_ssrc,
				"rtcp-fb-nack-pli", typeof (bool), true);

			Gee.List<Bytes> sets = _stream.parameter_sets;
			if (!sets.is_empty) {
				var sprop = new StringBuilder ();
				foreach (Bytes nal in sets) {
					if (sprop.len != 0)
						sprop.append_c (',');
					sprop.append (Base64.encode (nal.get_data ()));
				}
				caps.set_simple ("sprop-parameter-sets", typeof (string), sprop.str);
			}

			return caps;
		}
	}

	[CCode (cname = "idun_gst_register")]
	public bool gst_register (Gst.Plugin plugin) {
		return Gst.Element.register (plugin, "idunscreensrc", Gst.Rank.NONE, typeof (Idun.ScreenSrc));
	}
}
