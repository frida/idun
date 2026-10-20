qml_install_dir = get_option('libdir') / 'qt6' / 'qml' / 'Idun' / 'Screen'

moc_sources = qt.preprocess(
  moc_headers: ['idunscreen.h', 'plugin.h'],
  dependencies: qt_qml_dep,
)

shared_module('idunscreen', ['idunscreen.cpp', 'plugin.cpp', moc_sources],
  cpp_args: ['-DQT_NO_KEYWORDS'],
  dependencies: [idun_dep, qt_qml_dep, gst_dep, gst_gl_dep],
  install: true,
  install_dir: qml_install_dir,
  name_prefix: 'lib',
)

install_data('qmldir', install_dir: qml_install_dir)
