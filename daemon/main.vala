namespace Idun.DaemonMain {
	private static bool background = false;
	private static int idle_timeout = 30;

	private const OptionEntry[] options = {
		{ "background", 'b', OptionFlags.NONE, OptionArg.NONE, ref background, "Detach and exit when idle", null },
		{ "idle-timeout", 't', OptionFlags.NONE, OptionArg.INT, ref idle_timeout, "Exit after N seconds without clients", "N" },
		{ null }
	};

	private static int main (string[] args) {
		try {
			var context = new OptionContext ();
			context.set_help_enabled (true);
			context.add_main_entries (options, null);
			context.parse (ref args);
		} catch (OptionError e) {
			printerr ("%s\n", e.message);
			return 1;
		}

#if !WINDOWS
		if (background)
			Posix.setsid ();
#endif

		var loop = new MainLoop ();

		var server = new DaemonServer (Daemon.query_control_path (), background, (uint) idle_timeout, true);
		server.idle.connect (() => stop_and_quit (server, loop));

		int exit_code = 0;
		server.start.begin (null, (obj, res) => {
			try {
				server.start.end (res);
				announce_ready ();
			} catch (Efni.Error e) {
				if (e is Efni.Error.ADDRESS_IN_USE) {
					announce_ready ();
				} else {
					printerr ("%s\n", e.message);
					exit_code = 1;
				}
				loop.quit ();
			} catch (IOError e) {
				loop.quit ();
			}
		});

#if !WINDOWS
		Unix.signal_add (Posix.Signal.INT, () => {
			stop_and_quit (server, loop);
			return Source.REMOVE;
		});
		Unix.signal_add (Posix.Signal.TERM, () => {
			stop_and_quit (server, loop);
			return Source.REMOVE;
		});
#endif

		loop.run ();

		return exit_code;
	}

	private static void announce_ready () {
		stdout.printf ("ready\n");
		stdout.flush ();

#if !WINDOWS
		if (background)
			detach_from_terminal ();
#endif
	}

#if !WINDOWS
	private static void detach_from_terminal () {
		int fd = Posix.open ("/dev/null", Posix.O_RDWR);
		Posix.dup2 (fd, Posix.STDIN_FILENO);
		Posix.dup2 (fd, Posix.STDOUT_FILENO);
		Posix.dup2 (fd, Posix.STDERR_FILENO);
		Posix.close (fd);
	}
#endif

	private static bool stopping = false;

	private static void stop_and_quit (DaemonServer server, MainLoop loop) {
		if (stopping)
			return;
		stopping = true;

		server.stop.begin (null, (obj, res) => {
			try {
				server.stop.end (res);
			} catch (IOError e) {
			}
			loop.quit ();
		});
	}
}
