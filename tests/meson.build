test_sources = [
  'main.vala',
  'runner.vala',
  'async-harness.vala',
  'test-plist.vala',
  'test-opack.vala',
]

if build_daemon
  test_sources += 'test-daemon.vala'
endif

if host_os == 'linux'
  test_sources += 'test-network-stack.vala'
endif

if host_os != 'macos'
  test_sources += 'test-pair-crypto.vala'
  test_sources += 'test-courier-packed.vala'
  test_sources += 'test-message-identity.vala'
  test_sources += 'test-ngm-identity.vala'
  test_sources += 'test-tetra-message.vala'
endif

test_deps = [glib_dep, gobject_dep, gio_dep, gee_dep, json_glib_dep, efni_dep, idun_dep] + platform_deps

if host_os_family == 'darwin'
  add_languages('objc', native: false)
  test_sources += 'test-plist-darwin-glue.m'
  test_deps += dependency('appleframeworks', modules: ['Foundation'])
endif

runner = executable('idun-tests', test_sources,
  vala_args: [
    '--pkg=gio-2.0',
    '--pkg=json-glib-1.0',
    platform_vala_args,
  ],
  dependencies: test_deps,
)

test_env = {}
if build_daemon
  test_env += {'IDUN_TEST_IDUND': idund.full_path()}
endif

test('idun', runner,
  env: test_env,
  timeout: 120,
)
