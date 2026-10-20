project('idun', 'vala', 'c',
  version: run_command(find_program('python3'), files('tools' / 'detect-version.py'),
    capture: true,
    check: true).stdout().strip(),
  meson_version: '>=1.1.0',
  default_options: ['c_std=gnu99,c99'],
)

fs = import('fs')
cc = meson.get_compiler('c')

api_version = '1.0'

host_os_family = host_machine.system()
if host_os_family == 'android'
  host_os_family = 'linux'
endif
host_os = host_machine.subsystem().split('-')[0]

if host_os_family == 'darwin'
  add_languages('objc', native: false)
endif

ndebug = get_option('b_ndebug')
optimize_for_prod = ndebug == 'true' or (ndebug == 'if-release' and not get_option('debug'))

glib_dep = dependency('glib-2.0')
gobject_dep = dependency('gobject-2.0')
gio_dep = dependency('gio-2.0')
gee_dep = dependency('gee-0.8', default_options: [
  'default_library=static',
  'disable-introspection=true',
])
json_glib_dep = dependency('json-glib-1.0', version: '>=1.8', default_options: [
  'default_library=static',
  'introspection=disabled',
  'gtk_doc=disabled',
  'tests=false',
  'nls=disabled',
])
efni_dep = dependency('efni-1.0', default_options: ['default_library=static'])
add_project_arguments('--vapidir=' + efni_dep.get_variable('vapidir'), language: 'vala')

platform_deps = []
platform_reqs = []
platform_vala_args = []
platform_link_args = []
vala_defines = []

if host_os_family == 'windows'
  platform_deps += dependency('gio-windows-2.0')
else
  platform_deps += dependency('gio-unix-2.0')
  platform_vala_args += ['--pkg=gio-unix-2.0', '--pkg=posix']
endif

platform_deps += dependency('libnghttp2', default_options: ['default_library=static'])
platform_reqs += 'libnghttp2'
platform_vala_args += '--pkg=libnghttp2'

if host_os != 'macos'
  openssl_options = [
    'default_library=static',
    'cli=disabled',
  ]
  if host_os_family == 'windows' and cc.get_argument_syntax() != 'msvc'
    openssl_options += 'asm=disabled'
  endif
  platform_deps += dependency('openssl',
    modules: cc.get_argument_syntax() == 'msvc' ? ['OpenSSL::SSL'] : [],
    default_options: openssl_options,
  )
  platform_reqs += 'openssl'
  platform_vala_args += '--pkg=openssl'

  platform_deps += dependency('libngtcp2', default_options: ['default_library=static'])
  platform_reqs += 'libngtcp2'
  platform_vala_args += '--pkg=libngtcp2'

  ngtcp2_crypto_quictls_dep = dependency('libngtcp2_crypto_quictls', required: false, default_options: ['default_library=static'])
  if ngtcp2_crypto_quictls_dep.found()
    platform_deps += ngtcp2_crypto_quictls_dep
    platform_reqs += 'libngtcp2_crypto_quictls'
    platform_vala_args += '--pkg=libngtcp2_crypto_quictls'
  else
    platform_deps += dependency('libngtcp2_crypto_ossl', default_options: ['default_library=static'])
    platform_reqs += 'libngtcp2_crypto_ossl'
    platform_vala_args += '--pkg=libngtcp2_crypto_ossl'
    vala_defines += 'HAVE_NGTCP2_CRYPTO_OSSL'
  endif

  platform_deps += dependency('libusb-1.0', default_options: [
    'default_library=static',
    'examples=disabled',
    'tests=disabled',
  ])
  platform_reqs += 'libusb-1.0'
  platform_vala_args += '--pkg=libusb-1.0'

  lwip_options = [
    'default_library=static',
    'ipv4=disabled',
    'ipv6=enabled',
    'dns=disabled',
    'arp=disabled',
    'ethernet=enabled',
  ]
  if optimize_for_prod
    lwip_options += 'lwip_debug=disabled'
  else
    lwip_options += 'lwip_debug=enabled'
  endif
  platform_deps += dependency('lwip', default_options: lwip_options)
  platform_reqs += 'lwip'
  platform_vala_args += '--pkg=lwip'
endif

if host_os_family == 'windows'
  platform_vala_args += '--pkg=windows-windns'
  platform_link_args += ['-ldnsapi', '-liphlpapi', '-lsetupapi', '-lshell32']
elif host_os_family == 'darwin'
  platform_vala_args += [
    '--pkg=darwin-xnu',
    '--pkg=darwin-xpc',
    '--pkg=darwin-gcd',
  ]
  platform_link_args += ['-Wl,-framework,Foundation', '-Wl,-framework,CoreFoundation']
  if host_os == 'macos'
    platform_link_args += ['-Wl,-framework,AppKit']
  endif
elif host_os_family == 'linux'
  platform_vala_args += ['--pkg=linux', '--pkg=linux-if']
endif

local_vapidir = meson.current_source_dir() / 'vapi'

vala_flags = [
  '--vapidir=' + local_vapidir,
  '--define=' + host_os_family.to_upper(),
]
if host_os != host_os_family
  vala_flags += '--define=' + host_os.to_upper()
endif
foreach d : vala_defines
  vala_flags += '--define=' + d
endforeach
if gee_dep.type_name() not in ['internal', 'cmake']
  gee_prefix = gee_dep.get_variable('prefix', default_value: '')
  if gee_prefix != ''
    gee_vapidir = gee_prefix / 'share' / 'vala' / 'vapi'
    if fs.is_dir(gee_vapidir)
      vala_flags += '--vapidir=' + gee_vapidir
    endif
  endif
endif
add_project_arguments(vala_flags, language: 'vala')

c_flags = ['-DHAVE_' + host_os_family.to_upper()]
if host_os != host_os_family
  c_flags += '-DHAVE_' + host_os.to_upper()
endif
add_project_arguments(c_flags, language: ['c', 'objc'])

component_cflags = []
if optimize_for_prod
  component_cflags += [
    '-DG_DISABLE_ASSERT',
    '-DG_DISABLE_CHECKS',
    '-DG_DISABLE_CAST_CHECKS',
  ]
endif

gi_dep = dependency('gobject-introspection-1.0', required: false)
girdir = get_option('prefix') / get_option('datadir') / 'gir-1.0'
typelibdir = get_option('prefix') / get_option('libdir') / 'girepository-1.0'
gir_compiler = find_program('gi-compile-repository', 'g-ir-compiler', required: false)
build_typelib = gi_dep.found() and gir_compiler.found()
if build_typelib
  gi_girdir = gi_dep.get_variable('girdir')
  foreach gir : ['Gio-2.0.gir', 'Gee-0.8.gir', 'Json-1.0.gir']
    build_typelib = build_typelib and fs.exists(gi_girdir / gir)
  endforeach
endif
vapidir = get_option('prefix') / get_option('datadir') / 'vala' / 'vapi'
header_install_dir = get_option('includedir') / f'idun-@api_version@'

daemon_opt = get_option('daemon')
if daemon_opt.auto()
  build_daemon = host_os_family == 'windows' or host_os_family == 'linux'
else
  build_daemon = not daemon_opt.disabled()
endif
if build_daemon
  add_project_arguments('--define=HAVE_DAEMON', language: 'vala')
endif

cdata = configuration_data()
cdata.set_quoted('IDUN_CONFIG_LIBDIR', get_option('libdir'))
cdata.set_quoted('IDUN_CONFIG_BINDIR', get_option('bindir'))
configure_file(output: 'idun-config.h', configuration: cdata)

examples_opt = get_option('examples')
if examples_opt.auto()
  build_examples = not meson.is_subproject() and host_os_family != 'windows'
else
  build_examples = not examples_opt.disabled()
endif

gst_opt = get_option('gstreamer')
gst_dep = dependency('gstreamer-1.0', required: gst_opt)
gst_base_dep = dependency('gstreamer-base-1.0', required: gst_opt)
gst_app_dep = dependency('gstreamer-app-1.0', required: gst_opt)
build_gst = gst_dep.found() and gst_base_dep.found() and gst_app_dep.found()
if build_gst
  gst_plugindir = get_option('libdir') / 'gstreamer-1.0'
endif

quickshell_opt = get_option('quickshell')
qt = import('qt6', required: quickshell_opt)
qt_qml_dep = dependency('qt6', modules: ['Core', 'Gui', 'Qml', 'Quick'], required: quickshell_opt)
gst_gl_dep = dependency('gstreamer-gl-1.0', required: quickshell_opt)
build_quickshell = build_gst and qt.found() and qt_qml_dep.found() and gst_gl_dep.found()
if build_quickshell
  add_languages('cpp', native: false, required: true)
endif

tests_opt = get_option('tests')
if tests_opt.auto()
  build_tests = not meson.is_subproject() and meson.can_run_host_binaries()
else
  build_tests = not tests_opt.disabled()
endif

subdir('src')
if build_gst
  subdir('gst')
endif
if build_quickshell
  subdir('quickshell')
endif
if build_examples
  subdir('examples')
endif
if build_daemon
  subdir('daemon')
  if host_os_family == 'linux'
    subdir('data')
  endif
endif
if build_tests
  subdir('tests')
endif
