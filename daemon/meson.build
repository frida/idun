daemon_sources = ['main.vala']
daemon_kwargs = {}
if host_os_family == 'windows'
  daemon_sources += 'main-windows.c'
  daemon_kwargs += {'win_subsystem': 'windows'}
endif

idund = executable('idund', daemon_sources,
  vala_args: [
    '--pkg=gio-2.0',
    '--pkg=json-glib-1.0',
    platform_vala_args,
  ],
  dependencies: [glib_dep, gobject_dep, gio_dep, efni_dep, idun_dep],
  install: true,
  kwargs: daemon_kwargs,
)
