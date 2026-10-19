namespace Idun.Test {
	public void run (string[] args) {
		Environment.set_variable ("G_DEBUG", "fatal-warnings:fatal-criticals", true);
		GLib.Test.init (ref args);

		Idun.PlistTest.add_tests ();
		Idun.OpackTest.add_tests ();
#if HAVE_DAEMON
		Idun.DaemonTest.add_tests ();
#endif

		GLib.Test.run ();
	}
}
