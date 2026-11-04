#ifndef IDUN_SCREEN_PLUGIN_H
#define IDUN_SCREEN_PLUGIN_H

#include <QQmlExtensionPlugin>

class IdunScreenPlugin : public QQmlExtensionPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID QQmlExtensionInterface_iid)

public:
    void registerTypes(const char *uri) override;
};

#endif
