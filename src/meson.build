idun_sources = [
  'device-monitor.vala',
  'lockdown.vala',
  'installation-proxy.vala',
  'springboard-services.vala',
  'notification-proxy.vala',
  'pasteboard.vala',
  'screen-capture.vala',
  'display-stream.vala',
  'hid.vala',
  'core-device-info.vala',
  'instruments-device-info.vala',
  'instruments-application-listing.vala',
  'instruments-process-control.vala',
  'instruments-core-profile.vala',
  'lldb.vala',
  'discovery-service.vala',
  'app-service.vala',
  'trusted-service.vala',
  'plist-service.vala',
  'plist.vala',

  'transport' / 'channel-provider.vala',
  'transport' / 'xpc-connection.vala',
  'transport' / 'dtx-connection.vala',
  'transport' / 'network-stack.vala',
  'transport' / 'usbmux.vala',
  'transport' / 'dns.vala',

  'codec' / 'protobuf.vala',
  'codec' / 'xpc.vala',
  'codec' / 'dtx.vala',
  'codec' / 'keyed-archive.vala',
  'codec' / 'opack.vala',
  'codec' / 'courier-packed.vala',
  'codec' / 'cs-signature.vala',
  'codec' / 'kcdata.vala',
  'codec' / 'kdebug.vala',
  'codec' / 'kperfdata.vala',
  'codec' / 'debugger-mappings.vala',
]

if host_os != 'macos'
  idun_sources += [
    'transport' / 'device-monitor-portable.vala',
    'transport' / 'pairing.vala',
    'transport' / 'tunnel.vala',
    'transport' / 'tls-psk.vala',
    'transport' / 'virtual-network-stack.vala',
    'transport' / 'lwip-network-stack.vala',
    'transport' / 'usb.vala',
    'transport' / 'ncm.vala',

    'identity' / 'identity-store.vala',
    'identity' / 'apns-activation.vala',
    'identity' / 'apns-courier.vala',
    'identity' / 'grand-slam.vala',
    'identity' / 'ids-bag.vala',
    'identity' / 'ids-delegate.vala',
    'identity' / 'ids-auth-cert.vala',
    'identity' / 'message-identity.vala',
    'identity' / 'ngm-identity.vala',
    'identity' / 'ngm-peer-prekey.vala',
    'identity' / 'octagon-bottle.vala',
    'identity' / 'octagon-escrow-keys.vala',
    'identity' / 'octagon-crypto.vala',
    'identity' / 'octagon-escrow-record.vala',
    'identity' / 'cloudkit-code-operation.vala',
    'identity' / 'ckks-tlk-share.vala',
    'identity' / 'cloudkit-client.vala',
    'identity' / 'tetra-message.vala',
    'identity' / 'tetra-inner-message.vala',
    'identity' / 'tetra-binding.vala',
    'identity' / 'tetra-crypto.vala',
    'identity' / 'tetra-ratchet.vala',
    'identity' / 'tetra-root-context.vala',
    'identity' / 'tetra-session.vala',
    'identity' / 'ids-registration.vala',
    'identity' / 'ids-lookup.vala',
    'identity' / 'pair-crypto.vala',
    'identity' / 'facetime.vala',
    'identity' / 'facetime-media.vala',
    'identity' / 'identity-oracle.vala',
    'identity' / 'apple-root-ca.vala',
  ]
endif

if host_os == 'linux'
  idun_sources += 'transport' / 'tun-network-stack.vala'
endif

if build_daemon
  idun_sources += [
    'daemon' / 'daemon-protocol.vala',
    'daemon' / 'daemon-client.vala',
    'daemon' / 'daemon-server.vala',
  ]
  if host_os_family == 'windows'
    idun_sources += 'daemon' / 'daemon-glue-windows.c'
  else
    idun_sources += 'daemon' / 'daemon-glue-linux.c'
  endif
endif

if host_os_family == 'windows'
  idun_sources += [
    'transport' / 'device-monitor-windows.vala',
    'transport' / 'device-monitor-windows.c',
    'transport' / 'icon-helpers-windows.c',
  ]
elif host_os == 'macos'
  idun_sources += [
    'transport' / 'device-monitor-macos.vala',
    'transport' / 'device-monitor-darwin.m',
    'transport' / 'icon-helpers-darwin.m',
  ]
elif host_os_family == 'darwin'
  idun_sources += 'transport' / 'device-monitor-darwin.m'
elif host_os == 'linux'
  idun_sources += [
    'transport' / 'device-monitor-linux.vala',
    'transport' / 'device-monitor-unix.c',
  ]
else
  idun_sources += 'transport' / 'device-monitor-unix.c'
endif

if build_media
  idun_sources += [
    'media' / 'ice-agent.vala',
    'media' / 'rtp-media-session.vala',
    'media' / 'media-connection.vala',
  ]
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
  soversion: '0',
  install: true,
  install_dir: [true, header_install_dir, vapidir, girdir],
)

if build_typelib
  custom_target('idun-typelib',
    command: [
      gir_compiler,
      '--output', '@OUTPUT@',
      '--includedir=' + gi_girdir,
      '--includedir=' + efni_dep.get_variable('girdir'),
      meson.current_build_dir() / idun_gir_name,
    ],
    output: f'Idun-@api_version@.typelib',
    depends: idun,
    install: true,
    install_dir: typelibdir,
  )
endif

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
  requires: ['glib-2.0', 'gobject-2.0', 'gio-2.0', 'gee-0.8', f'efni-@api_version@'],
  requires_private: ['json-glib-1.0'] + platform_reqs,
  libraries_private: platform_link_args,
  subdirs: f'idun-@api_version@',
)
