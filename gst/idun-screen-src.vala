namespace Idun {
	public class ScreenSrc : Gst.Bin {
		public DisplayStream stream {
			get {
				return _stream;
			}
			set {
				_stream = value;
				if (_stream != null && session == null)
					assemble ();
			}
		}

		private DisplayStream _stream;

		private Gst.App.Src rtp_src;
		private Gst.App.Src rtcp_src;
		private Gst.App.Sink rtcp_sink;
		private Gst.Element session;
		private Gst.Element depayloader;
		private Gst.Element output;
		private ulong rtp_handler;
		private ulong rtcp_handler;

		private const int RTP_PROFILE_AVPF = 3;

		class construct {
			add_pad_template (new Gst.PadTemplate ("src", SRC, ALWAYS, new Gst.Caps.empty_simple ("video/x-h264")));
			set_static_metadata ("Idun screen source", "Source/Video",
				"Receives a CoreDevice display stream as H.264",
				"Ole André Vadla Ravnås <oleavr@frida.re>");
		}

		public override Gst.StateChangeReturn change_state (Gst.StateChange transition) {
			if (transition == NULL_TO_READY) {
				rtp_handler = _stream.rtp.connect (on_rtp);
				rtcp_handler = _stream.rtcp.connect (on_rtcp);
			}

			Gst.StateChangeReturn result = base.change_state (transition);

			if (transition == READY_TO_NULL) {
				_stream.disconnect (rtp_handler);
				_stream.disconnect (rtcp_handler);
			}

			return result;
		}

		private void assemble () {
			rtp_src = (Gst.App.Src) Gst.ElementFactory.make ("appsrc", "rtp_src");
			rtcp_src = (Gst.App.Src) Gst.ElementFactory.make ("appsrc", "rtcp_src");
			rtcp_sink = (Gst.App.Sink) Gst.ElementFactory.make ("appsink", "rtcp_sink");
			session = Gst.ElementFactory.make ("rtpbin", "session");
			depayloader = Gst.ElementFactory.make ("rtph264depay", "depayloader");
			output = Gst.ElementFactory.make ("queue", "output");

			rtp_src.caps = describe_payload ();
			rtp_src.set ("is-live", true, "format", Gst.Format.TIME, "do-timestamp", true);
			rtcp_src.caps = new Gst.Caps.empty_simple ("application/x-rtcp");
			rtcp_src.set ("is-live", true);
			rtcp_sink.set ("emit-signals", true, "sync", false, "async", false);
			session.set ("rtp-profile", RTP_PROFILE_AVPF);

			add_many (rtp_src, rtcp_src, rtcp_sink, session, depayloader, output);

			rtp_src.link_pads ("src", session, "recv_rtp_sink_0");
			rtcp_src.link_pads ("src", session, "recv_rtcp_sink_0");
			session.link_pads ("send_rtcp_src_0", rtcp_sink, "sink");
			depayloader.link (output);

			GLib.Signal.connect (session, "request-pt-map", (GLib.Callback) on_request_pt_map, this);
			session.pad_added.connect (on_rtp_pad_added);
			rtcp_sink.new_sample.connect (on_rtcp_ready);

			var ghost = new Gst.GhostPad.from_template ("src", output.get_static_pad ("src"), get_pad_template ("src"));
			ghost.set_active (true);
			add_pad (ghost);
		}

		private void on_rtp (Bytes data) {
			rtp_src.push_buffer (new Gst.Buffer.wrapped_bytes (data));
		}

		private void on_rtcp (Bytes data) {
			rtcp_src.push_buffer (new Gst.Buffer.wrapped_bytes (data));
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
			return new Gst.Caps.simple ("application/x-rtp",
				"media", typeof (string), "video",
				"clock-rate", typeof (int), (int) _stream.clock_rate,
				"encoding-name", typeof (string), "H264",
				"payload", typeof (int), (int) _stream.payload_type,
				"ssrc", typeof (uint), _stream.remote_ssrc,
				"rtcp-fb-nack-pli", typeof (bool), true);
		}
	}

	[CCode (cname = "idun_gst_register")]
	public bool gst_register (Gst.Plugin plugin) {
		return Gst.Element.register (plugin, "idunscreensrc", Gst.Rank.NONE, typeof (Idun.ScreenSrc));
	}
}
