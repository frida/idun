executable('coredevice-demo', 'coredevice-demo.vala',
  vala_args: ['--pkg=gio-2.0', platform_vala_args],
  dependencies: [idun_dep, json_glib_dep],
)

if host_os != 'macos'
  executable('identity-demo', 'identity-demo.vala',
    vala_args: ['--pkg=gio-2.0', platform_vala_args],
    dependencies: [idun_dep, json_glib_dep],
  )
  executable('facetime-decline', 'facetime-decline.vala',
    vala_args: ['--pkg=gio-2.0', '--pkg=gee-0.8', platform_vala_args],
    dependencies: [idun_dep, json_glib_dep],
  )
endif
