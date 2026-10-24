namespace Idun.Test {
	public void run (string[] args) {
		Environment.set_variable ("G_DEBUG", "fatal-warnings:fatal-criticals", true);
#if HAVE_DAEMON
		string runtime_dir = isolate_daemon ();
#endif
		GLib.Test.init (ref args);
#if !MACOS
		Gst.init (ref args);
#endif

		Idun.PlistTest.add_tests ();
		Idun.OpackTest.add_tests ();
#if !MACOS
		Idun.PairCryptoTest.add_tests ();
		Idun.CourierPackedTest.add_tests ();
		Idun.MessageIdentityTest.add_tests ();
		Idun.NgmIdentityTest.add_tests ();
		Idun.NgmPeerPrekeyTest.add_tests ();
		Idun.TetraMessageTest.add_tests ();
		Idun.IceAgentTest.add_tests ();
		Idun.RtpMediaSessionTest.add_tests ();
		Idun.TetraCryptoTest.add_tests ();
		Idun.TetraRatchetTest.add_tests ();
		Idun.TetraSessionTest.add_tests ();
		Idun.TetraAuthDataTest.add_tests ();
#endif
#if HAVE_DAEMON
		Idun.DaemonTest.add_tests ();
#endif
#if LINUX
		Idun.NetworkStackTest.add_tests ();
#endif

		GLib.Test.run ();

#if HAVE_DAEMON
		DirUtils.remove (Path.build_filename (runtime_dir, "idun"));
		DirUtils.remove (runtime_dir);
#endif
	}

#if HAVE_DAEMON
	private string isolate_daemon () {
		string runtime_dir;
		try {
			runtime_dir = DirUtils.make_tmp ("idun-tests-XXXXXX");
		} catch (FileError e) {
			assert_not_reached ();
		}
		Environment.set_variable ("XDG_RUNTIME_DIR", runtime_dir, true);
		Environment.set_variable ("XDG_CACHE_HOME", runtime_dir, true);
		Environment.set_variable ("XDG_CONFIG_HOME", runtime_dir, true);
		Environment.unset_variable ("DBUS_SESSION_BUS_ADDRESS");
		return runtime_dir;
	}
#endif
}
