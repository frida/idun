#include "plugin.h"

#include "idunscreen.h"

#include <qqml.h>
#include <gst/gst.h>

void IdunScreenPlugin::registerTypes(const char *uri)
{
    gst_init(nullptr, nullptr);
    qmlRegisterType<IdunScreen>(uri, 1, 0, "IdunScreen");
}
