using Efni;

namespace Idun {
	/**
	 * Observes and posts Darwin notifications on the device through the notification proxy service.
	 */
	public sealed class NotificationProxyClient : Object {
		public signal void closed (Efni.Error? error);

		/**
		 * Emitted when an observed notification fires on the device.
		 */
		public signal void notification (string name);

		private PlistServiceClient client;
		private bool is_closed = false;
		private Cancellable io_cancellable = new Cancellable ();

		private const string SERVICE_NAME = "com.apple.mobile.notification_proxy";

		public static async NotificationProxyClient open (Device device, Cancellable? cancellable = null) throws Efni.Error, IOError {
			IOStream stream = yield device.open_lockdown_service (SERVICE_NAME, cancellable);
			return new NotificationProxyClient (stream);
		}

		private NotificationProxyClient (IOStream stream) {
			client = new PlistServiceClient (stream);
			process_incoming_messages.begin ();
		}

		public async void close (Cancellable? cancellable = null) throws IOError {
			if (is_closed)
				return;
			is_closed = true;

			io_cancellable.cancel ();
			yield client.close (cancellable);
		}

		/**
		 * Asks the device to relay the named notification whenever it is posted.
		 */
		public void observe (string name) {
			send_command ("ObserveNotification", name);
		}

		/**
		 * Posts a notification on the device.
		 */
		public void post (string name) {
			send_command ("PostNotification", name);
		}

		private void send_command (string command, string name) {
			var message = new Plist ();
			message.set_string ("Command", command);
			message.set_string ("Name", name);
			client.write_message (message);
		}

		private async void process_incoming_messages () {
			Efni.Error? error = null;
			try {
				while (true) {
					Plist message = yield client.read_message (io_cancellable);

					unowned string command = message.get_string ("Command");
					if (command == "RelayNotification") {
						notification (message.get_string ("Name"));
					} else if (command == "ProxyDeath") {
						error = new Efni.Error.TRANSPORT ("Notification proxy terminated");
						break;
					}
				}
			} catch (GLib.Error e) {
				if (!(e is IOError.CANCELLED))
					error = new Efni.Error.TRANSPORT ("%s", e.message);
			}

			if (!is_closed) {
				is_closed = true;
				closed (error);
			}
		}
	}
}
