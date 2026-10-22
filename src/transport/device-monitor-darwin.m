#include "icon-helpers-darwin.h"
#include "idun.h"

typedef struct _IdunModel IdunModel;

struct _IdunModel
{
  gint product_id;
  const gchar * name;
  const gchar * icon;
};

static const IdunModel idun_models[] =
{
  { -1,     "iOS Device",          "com.apple.iphone-4-black" },
  { 0x1290, "iPhone",              "com.apple.iphone" },
  { 0x1291, "iPod Touch 1G",       "com.apple.ipod-touch" },
  { 0x1292, "iPhone 3G",           "com.apple.iphone-3g" },
  { 0x1293, "iPod Touch 2G",       "com.apple.ipod-touch-2" },
  { 0x1294, "iPhone 3GS",          "com.apple.iphone-3g" },
  { 0x1296, "iPod Touch 3G",       "com.apple.ipod-touch-2" },
  { 0x1297, "iPhone 4",            "com.apple.iphone-4-black" },
  { 0x1299, "iPod Touch 3G",       "com.apple.ipod-touch-2" },
  { 0x129a, "iPad",                "com.apple.ipad" },
  { 0x129c, "iPhone 4",            "com.apple.iphone-4-black" },
  { 0x129e, "iPod Touch 4G",       "com.apple.ipod-touch-4-black" },
  { 0x129f, "iPad 2",              "com.apple.ipad" },
  { 0x12a0, "iPhone 4S",           "com.apple.iphone-4-black" },
  { 0x12a2, "iPad 2",              "com.apple.ipad" },
  { 0x12a3, "iPad 2",              "com.apple.ipad" },
  { 0x12a4, "iPad 3",              "com.apple.ipad" },
  { 0x12a5, "iPad 3",              "com.apple.ipad" },
  { 0x12a6, "iPad 3",              "com.apple.ipad" },
  { 0x12a8, "iPhone",              "com.apple.iphone-4-black" },
  { 0x12a9, "iPad 2",              "com.apple.ipad" },
  { 0x12aa, "iPod Touch 5G",       "com.apple.ipod-touch-4-black" },
  { 0x12ab, "iPad",                "com.apple.ipad" }
};

void
_idun_usbmux_backend_extract_details_for_device (gint product_id, const char * udid, char ** name, GVariant ** icon,
    GError ** error)
{
  const IdunModel * model;
  guint i;
  gchar * filename;

  for (model = NULL, i = 1; i != G_N_ELEMENTS (idun_models) && model == NULL; i++)
  {
    if (idun_models[i].product_id == product_id)
      model = &idun_models[i];
  }
  if (model == NULL)
    model = &idun_models[0];

  filename = g_strconcat ("/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/", model->icon, ".icns", NULL);
  *name = g_strdup (model->name);
  *icon = _idun_icon_from_file (filename, 16, 16);
  g_free (filename);
}
