test_sources = [
  'main.vala',
  'runner.vala',
  'test-plist.vala',
  'test-opack.vala',
]

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

test('idun', runner,
  timeout: 120,
)
