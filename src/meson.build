idun_sources = [
  'channel-provider.vala',
  'device-monitor.vala',
  'xpc.vala',
  'dtx.vala',
  'lockdown.vala',
  'installation-proxy.vala',
  'springboard-services.vala',
  'lldb.vala',
  'debugger-mappings.vala',
  'usbmux.vala',
  'dns.vala',
  'keyed-archive.vala',
  'plist.vala',
  'plist-service.vala',
  'opack.vala',
  'kcdata.vala',
  'kdebug.vala',
  'kperfdata.vala',
  'cs-signature.vala',
  'network-stack.vala',
]

if host_os != 'macos'
  idun_sources += [
    'device-monitor-portable.vala',
    'pairing.vala',
    'tunnel.vala',
    'tls-psk.vala',
    'virtual-network-stack.vala',
    'lwip-network-stack.vala',
    'usb.vala',
    'ncm.vala',
  ]
endif

if host_os == 'linux'
  idun_sources += 'tun-network-stack.vala'
endif

if build_daemon
  idun_sources += [
    'daemon-protocol.vala',
    'daemon-glue.c',
    'daemon-client.vala',
    'daemon-server.vala',
  ]
endif

if host_os_family == 'windows'
  idun_sources += [
    'device-monitor-windows.vala',
    'device-monitor-windows.c',
    'icon-helpers-windows.c',
  ]
elif host_os == 'macos'
  idun_sources += [
    'device-monitor-macos.vala',
    'device-monitor-darwin.m',
    'icon-helpers-darwin.m',
  ]
elif host_os_family == 'darwin'
  idun_sources += 'device-monitor-darwin.m'
elif host_os == 'linux'
  idun_sources += [
    'device-monitor-linux.vala',
    'device-monitor-unix.c',
  ]
else
  idun_sources += 'device-monitor-unix.c'
endif

idun_gir_name = f'Idun-@api_version@.gir'

idun = library('idun-' + api_version, idun_sources,
  c_args: component_cflags,
  objc_args: component_cflags,
  include_directories: include_directories('..'),
  vala_header: 'idun.h',
  vala_vapi: f'idun-@api_version@.vapi',
  vala_gir: idun_gir_name,
  vala_args: [
    '--pkg=gio-2.0',
    '--pkg=json-glib-1.0',
    '--pkg=idun-config',
    platform_vala_args,
  ],
  link_args: platform_link_args,
  dependencies: [glib_dep, gobject_dep, gio_dep, gee_dep, json_glib_dep, efni_dep] + platform_deps,
  install: true,
  install_dir: [true, header_install_dir, vapidir, girdir],
)

idun_dep = declare_dependency(
  include_directories: include_directories('.'),
  link_args: platform_link_args,
  link_with: idun,
  dependencies: [glib_dep, gobject_dep, gio_dep, gee_dep, json_glib_dep, efni_dep] + platform_deps,
  variables: {'vapidir': local_vapidir},
)

meson.override_dependency(f'idun-@api_version@', idun_dep)

pkg = import('pkgconfig')
pkg.generate(idun,
  filebase: f'idun-@api_version@',
  name: 'Idun',
  version: meson.project_version(),
  description: 'Library for talking to Apple devices',
  requires: ['glib-2.0', 'gobject-2.0', 'gio-2.0', 'json-glib-1.0', f'efni-@api_version@'],
  requires_private: ['gee-0.8'] + platform_reqs,
  libraries_private: platform_link_args,
  subdirs: f'idun-@api_version@',
)
