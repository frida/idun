#ifndef IDUN_SCREEN_H
#define IDUN_SCREEN_H

#include <QQuickItem>
#include <gst/gst.h>
#include <idun.h>

class IdunScreen : public QQuickItem
{
    Q_OBJECT
    Q_PROPERTY(QString udid READ udid WRITE setUdid NOTIFY udidChanged)

public:
    explicit IdunScreen(QQuickItem *parent = nullptr);
    ~IdunScreen() override;

    QString udid() const;
    void setUdid(const QString &udid);

Q_SIGNALS:
    void udidChanged();
    void streaming();
    void failed(const QString &message);

protected:
    void componentComplete() override;
    void geometryChange(const QRectF &newGeometry, const QRectF &oldGeometry) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;

private:
    void startWorker();
    void onStreamReady(IdunDisplayStream *stream, IdunHidClient *hid);
    void buildPipeline(IdunDisplayStream *stream);
    void dispatchTouch(void (*fn)(IdunHidClient *, double, double, int), double x, double y);

    static gpointer workerMain(gpointer data);
    static void onDeviceAttached(IdunDeviceMonitor *monitor, IdunDevice *device, IdunScreen *self);
    static void onStreamOpened(GObject *sourceObject, GAsyncResult *res, gpointer userData);
    static void onHidOpened(GObject *sourceObject, GAsyncResult *res, gpointer userData);
    static void onDecoderPadAdded(GstElement *decoder, GstPad *pad, IdunScreen *self);

    QString m_udid;
    bool m_started = false;

    GThread *m_worker = nullptr;
    GMainContext *m_context = nullptr;
    GMainLoop *m_loop = nullptr;
    IdunDeviceMonitor *m_monitor = nullptr;
    IdunHidClient *m_hid = nullptr;

    GstElement *m_pipeline = nullptr;
    GstElement *m_upload = nullptr;
    QQuickItem *m_videoItem = nullptr;
    guint m_deviceWidth = 0;
    guint m_deviceHeight = 0;
};

#endif
