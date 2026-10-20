using Efni;

namespace Idun {
	public sealed class HidClient : Object {
		public signal void closed (Efni.Error? error);

		private XpcConnection connection;
		private Gee.Deque<DigitizerEvent> pending_events = new Gee.ArrayQueue<DigitizerEvent> ();
		private bool sending = false;
		private Cancellable io_cancellable = new Cancellable ();

		private const uint HOME_GESTURE_STEPS = 8;
		private const uint HOME_GESTURE_STEP_INTERVAL_MS = 16;

		public static async HidClient open (Device device, Cancellable? cancellable = null) throws Efni.Error, IOError {
			var channel = yield device.open_tcp_channel ("com.apple.coredevice.hid.indigo", ALLOW_TUNNEL, cancellable);
			return new HidClient (channel.stream);
		}

		private HidClient (IOStream stream) {
			connection = new XpcConnection (stream);
			connection.close.connect (on_close);
			connection.activate ();
		}

		public void close () {
			io_cancellable.cancel ();
			connection.cancel ();
		}

		public void touch_down (double x, double y, DigitizerEdge edge = NONE) {
			enqueue (new DigitizerEvent (BEGAN, x, y, edge));
		}

		public void touch_move (double x, double y, DigitizerEdge edge = NONE) {
			DigitizerEvent? last = pending_events.peek_tail ();
			if (last != null && last.phase == MOVED) {
				last.x = x;
				last.y = y;
				last.edge = edge;
				return;
			}

			enqueue (new DigitizerEvent (MOVED, x, y, edge));
		}

		public void touch_up (double x, double y, DigitizerEdge edge = NONE) {
			enqueue (new DigitizerEvent (ENDED, x, y, edge));
		}

		public async void perform_home_gesture (Cancellable? cancellable = null) throws IOError {
			touch_down (0.5, 1.0, BOTTOM);
			for (uint i = 1; i <= HOME_GESTURE_STEPS; i++) {
				yield sleep (HOME_GESTURE_STEP_INTERVAL_MS, cancellable);
				touch_move (0.5, 1.0 - 0.5 * i / HOME_GESTURE_STEPS, BOTTOM);
			}
			touch_up (0.5, 0.5, BOTTOM);
		}

		private async void sleep (uint duration_ms, Cancellable? cancellable) throws IOError {
			var timeout_source = new TimeoutSource (duration_ms);
			timeout_source.set_callback (sleep.callback);
			timeout_source.attach (MainContext.get_thread_default ());

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (sleep.callback);
			cancel_source.attach (MainContext.get_thread_default ());

			yield;

			cancel_source.destroy ();
			timeout_source.destroy ();

			if (cancellable != null)
				cancellable.set_error_if_cancelled ();
		}

		private void enqueue (DigitizerEvent event) {
			pending_events.offer_tail (event);
			if (!sending)
				send_pending_events.begin ();
		}

		private async void send_pending_events () {
			sending = true;

			DigitizerEvent? event;
			while ((event = pending_events.poll_head ()) != null) {
				try {
					yield send (event);
				} catch (GLib.Error e) {
					break;
				}
			}

			sending = false;
		}

		private async void send (DigitizerEvent event) throws Efni.Error, IOError {
			var request = new XpcBodyBuilder ()
				.begin_dictionary ()
					.set_member_name ("featureIdentifier")
					.add_string_value ("com.apple.coredevice.feature.remote.hid.digitizer")
					.set_member_name ("messageType")
					.add_string_value ("IndigoDigitizerEvent")
					.set_member_name ("payload")
					.begin_dictionary ();
			foreach (unowned string point in new string[] { "pointOne", "pointTwo" }) {
				request
					.set_member_name (point)
					.begin_dictionary ()
						.set_member_name ("x")
						.add_double_value (event.x)
						.set_member_name ("y")
						.add_double_value (event.y)
					.end_dictionary ();
			}
			request
						.set_member_name ("eventType")
						.add_uint64_value (event.phase)
						.set_member_name ("edge")
						.add_uint64_value (event.edge)
						.set_member_name ("target")
						.add_uint64_value (TARGET_MAIN_SCREEN)
					.end_dictionary ()
					.set_member_name ("isBarrier")
					.add_bool_value (false)
				.end_dictionary ();

			yield connection.request (request.build (), io_cancellable);
		}

		private void on_close (Efni.Error? error) {
			closed (error);
		}

		private const uint64 TARGET_MAIN_SCREEN = 1;

		private class DigitizerEvent {
			public DigitizerPhase phase;
			public double x;
			public double y;
			public DigitizerEdge edge;

			public DigitizerEvent (DigitizerPhase phase, double x, double y, DigitizerEdge edge) {
				this.phase = phase;
				this.x = x;
				this.y = y;
				this.edge = edge;
			}
		}
	}

	public enum DigitizerPhase {
		BEGAN = 0,
		MOVED = 1,
		ENDED = 2,
	}

	public enum DigitizerEdge {
		NONE = 0,
		BOTTOM = 3,
	}
}
