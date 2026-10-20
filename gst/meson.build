gst_plugin = shared_module('gstidun', 'idun-screen-src.vala', 'gstidun-plugin.c',
  vala_args: ['--pkg=gstreamer-1.0', '--pkg=gstreamer-base-1.0', '--pkg=gstreamer-app-1.0'],
  c_args: ['-DPACKAGE="idun"', '-DVERSION="' + meson.project_version() + '"'],
  dependencies: [idun_dep, gst_dep, gst_base_dep, gst_app_dep],
  install: true,
  install_dir: gst_plugindir,
)
