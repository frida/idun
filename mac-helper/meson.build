install_data('idun-mac-oracle.py',
  install_dir: get_option('bindir'),
  install_mode: 'rwxr-xr-x',
)

install_data('idun-mac-host.py',
  install_dir: get_option('bindir'),
)

frida_compile = find_program(
  'agent' / 'node_modules' / '.bin' / 'frida-compile',
)

custom_target('idun-mac-agent',
  input: 'agent' / 'index.ts',
  output: 'idun-mac-agent.js',
  command: [frida_compile, '@INPUT@', '-o', '@OUTPUT@', '-c'],
  install: true,
  install_dir: get_option('bindir'),
)
