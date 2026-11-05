daemon_sources = ['main.vala']
daemon_kwargs = {}
daemon_deps = [glib_dep, gobject_dep, gio_dep, efni_dep, idun_dep]
daemon_vala_args = []
if host_os != 'macos' and not have_shared_glib
  gioopenssl_dep = dependency('gioopenssl', default_options: [
    'gnutls=disabled',
    'openssl=enabled',
    'apple=disabled',
    'libproxy=disabled',
    'gnome_proxy=disabled',
    'tests=false',
  ])
  daemon_deps += gioopenssl_dep
  daemon_vala_args += [
    '--pkg=gioopenssl',
    '--vapidir=' + gioopenssl_dep.get_variable('vapidir'),
    '--define=HAVE_GIOOPENSSL',
  ]
endif
if host_os_family == 'windows'
  daemon_sources += 'main-windows.c'
  daemon_kwargs += {'win_subsystem': 'windows'}
endif

idund = executable('idund', daemon_sources,
  vala_args: [
    '--pkg=gio-2.0',
    '--pkg=json-glib-1.0',
    platform_vala_args,
    daemon_vala_args,
  ],
  dependencies: daemon_deps,
  install: true,
  kwargs: daemon_kwargs,
)
