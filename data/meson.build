data_conf = configuration_data()
data_conf.set('bindir', get_option('prefix') / get_option('bindir'))

configure_file(
  input: 'io.github.frida.Idun1.service.in',
  output: 'io.github.frida.Idun1.service',
  configuration: data_conf,
  install: true,
  install_dir: get_option('datadir') / 'dbus-1' / 'services',
)

configure_file(
  input: 'idund.service.in',
  output: 'idund.service',
  configuration: data_conf,
  install: true,
  install_dir: get_option('prefix') / 'lib' / 'systemd' / 'user',
)
