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

  executable('facetime-capture', 'facetime-capture.vala',
    vala_args: ['--pkg=gio-2.0', '--pkg=gee-0.8', platform_vala_args],
    dependencies: [idun_dep, json_glib_dep],
  )

  executable('facetime-accept', 'facetime-accept.vala',
    vala_args: ['--pkg=gio-2.0', '--pkg=gee-0.8', platform_vala_args],
    dependencies: [idun_dep, json_glib_dep],
  )
  executable('facetime-probe', 'facetime-probe.vala',
    vala_args: ['--pkg=gio-2.0', '--pkg=gee-0.8', platform_vala_args],
    dependencies: [idun_dep, json_glib_dep],
  )
  executable('relay-probe', 'relay-probe.vala',
    vala_args: ['--pkg=gio-2.0', '--pkg=gee-0.8', platform_vala_args],
    dependencies: [idun_dep, json_glib_dep],
  )
  executable('facetime-ktblobs', 'facetime-ktblobs.vala',
    vala_args: ['--pkg=gio-2.0', '--pkg=gee-0.8', platform_vala_args],
    dependencies: [idun_dep, json_glib_dep],
  )
endif
if host_machine.system() != 'darwin'
  executable('octagon-probe', 'octagon-probe.vala',
    vala_args: ['--pkg=gio-2.0', '--pkg=gee-0.8', platform_vala_args],
    dependencies: [idun_dep, json_glib_dep],
  )
  executable('escrow-probe', 'escrow-probe.vala',
    vala_args: ['--pkg=gio-2.0', '--pkg=gee-0.8', platform_vala_args],
    dependencies: [idun_dep, json_glib_dep],
  )
  executable('octagon-recover', 'octagon-recover.vala',
    vala_args: ['--pkg=gio-2.0', '--pkg=gee-0.8', platform_vala_args],
    dependencies: [idun_dep, json_glib_dep],
  )
endif
if host_machine.system() != 'darwin'
  executable('facetime-decrypt', 'facetime-decrypt.vala',
    vala_args: ['--pkg=gio-2.0', '--pkg=gee-0.8', platform_vala_args],
    dependencies: [idun_dep, json_glib_dep],
  )
endif
