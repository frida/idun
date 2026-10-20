#include <gst/gst.h>

gboolean idun_gst_register (GstPlugin * plugin);

static gboolean
plugin_init (GstPlugin * plugin)
{
  return idun_gst_register (plugin);
}

GST_PLUGIN_DEFINE (GST_VERSION_MAJOR, GST_VERSION_MINOR, idun,
    "Idun CoreDevice media integration", plugin_init, "1.0", "LGPL", "idun", "https://frida.re")
