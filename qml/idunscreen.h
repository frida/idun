#ifndef IDUN_SCREEN_H
#define IDUN_SCREEN_H

#include <QQuickItem>
#include <QVideoSink>
#include <functional>
#include <gst/gst.h>
#include <idun.h>

class IdunScreen : public QQuickItem
{
    Q_OBJECT
    Q_PROPERTY(QString udid READ udid WRITE setUdid NOTIFY udidChanged)
    Q_PROPERTY(uint deviceWidth READ deviceWidth NOTIFY deviceSizeChanged)
    Q_PROPERTY(uint deviceHeight READ deviceHeight NOTIFY deviceSizeChanged)

public:
    explicit IdunScreen(QQuickItem *parent = nullptr);
    ~IdunScreen() override;

    QString udid() const;
    void setUdid(const QString &udid);
    uint deviceWidth() const;
    uint deviceHeight() const;

    Q_INVOKABLE void home();

Q_SIGNALS:
    void udidChanged();
    void deviceSizeChanged();
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
    bool buildPipeline(IdunDisplayStream *stream);
    QQuickItem *createVideoOutput();
    void pushFrame(GstSample *sample);
    void dispatchTouch(void (*fn)(IdunHidClient *, double, double, IdunDigitizerEdge), double x, double y);
    void invokeOnWorker(std::function<void ()> fn);
    void fail(const QString &message);

    static gpointer workerMain(gpointer data);
    static void onMonitorStarted(GObject *sourceObject, GAsyncResult *res, gpointer userData);
    static void onDeviceAttached(IdunDeviceMonitor *monitor, IdunDevice *device, IdunScreen *self);
    static void onStreamOpened(GObject *sourceObject, GAsyncResult *res, gpointer userData);
    static void onHidOpened(GObject *sourceObject, GAsyncResult *res, gpointer userData);
    static void onDecoderPadAdded(GstElement *decoder, GstPad *pad, IdunScreen *self);
    static GstFlowReturn onNewSample(GstElement *sink, IdunScreen *self);
    static GstBusSyncReply onBusMessage(GstBus *bus, GstMessage *message, gpointer userData);

    QString m_udid;
    bool m_started = false;

    GThread *m_worker = nullptr;
    GMainContext *m_context = nullptr;
    GMainLoop *m_loop = nullptr;
    IdunDeviceMonitor *m_monitor = nullptr;
    IdunHidClient *m_hid = nullptr;

    GstElement *m_pipeline = nullptr;
    GstElement *m_convert = nullptr;
    QQuickItem *m_videoItem = nullptr;
    QVideoSink *m_videoSink = nullptr;
    uint m_deviceWidth = 0;
    uint m_deviceHeight = 0;
};

#endif
