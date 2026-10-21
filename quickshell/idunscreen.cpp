#include "idunscreen.h"

#include <QMouseEvent>
#include <QQmlComponent>
#include <QQmlEngine>
#include <QVideoFrame>
#include <QVideoFrameFormat>
#include <gst/app/gstappsink.h>
#include <gst/video/video.h>

namespace {

struct OpenCtx
{
    IdunScreen *self;
    IdunDevice *device;
    IdunDisplayStream *stream;
};

const char *const pipelineElements[] = { "idunscreensrc", "h264parse", "decodebin3", "videoconvert", "appsink" };

gboolean invokeCpp(gpointer data)
{
    auto fn = static_cast<std::function<void ()> *>(data);
    (*fn)();
    return G_SOURCE_REMOVE;
}

void destroyCpp(gpointer data)
{
    delete static_cast<std::function<void ()> *>(data);
}

} // namespace

IdunScreen::IdunScreen(QQuickItem *parent)
    : QQuickItem(parent)
{
    setFlag(ItemHasContents, false);
    setAcceptedMouseButtons(Qt::LeftButton);
}

IdunScreen::~IdunScreen()
{
    if (m_loop != nullptr)
        g_main_loop_quit(m_loop);
    if (m_worker != nullptr)
        g_thread_join(m_worker);

    if (m_pipeline != nullptr) {
        gst_element_set_state(m_pipeline, GST_STATE_NULL);
        gst_object_unref(m_pipeline);
    }

    g_clear_object(&m_hid);
    g_clear_object(&m_monitor);
    if (m_loop != nullptr)
        g_main_loop_unref(m_loop);
    if (m_context != nullptr)
        g_main_context_unref(m_context);
}

QString IdunScreen::udid() const
{
    return m_udid;
}

void IdunScreen::setUdid(const QString &udid)
{
    if (udid == m_udid)
        return;
    m_udid = udid;
    Q_EMIT udidChanged();
}

uint IdunScreen::deviceWidth() const
{
    return m_deviceWidth;
}

uint IdunScreen::deviceHeight() const
{
    return m_deviceHeight;
}

void IdunScreen::home()
{
    if (m_hid == nullptr)
        return;
    IdunHidClient *hid = m_hid;
    invokeOnWorker([hid]() {
        idun_hid_client_perform_home_gesture(hid, nullptr, nullptr, nullptr);
    });
}

void IdunScreen::componentComplete()
{
    QQuickItem::componentComplete();
    startWorker();
}

void IdunScreen::startWorker()
{
    if (m_started)
        return;
    m_started = true;

    m_context = g_main_context_new();
    m_loop = g_main_loop_new(m_context, FALSE);
    m_worker = g_thread_new("idun-screen", workerMain, this);
}

gpointer IdunScreen::workerMain(gpointer data)
{
    auto self = static_cast<IdunScreen *>(data);

    g_main_context_push_thread_default(self->m_context);

    self->m_monitor = idun_device_monitor_new();
    g_signal_connect(self->m_monitor, "device-attached", G_CALLBACK(onDeviceAttached), self);
    idun_device_monitor_start(self->m_monitor, nullptr, onMonitorStarted, self);

    g_main_loop_run(self->m_loop);

    g_main_context_pop_thread_default(self->m_context);
    return nullptr;
}

void IdunScreen::onMonitorStarted(GObject *sourceObject, GAsyncResult *res, gpointer userData)
{
    auto self = static_cast<IdunScreen *>(userData);
    GError *error = nullptr;

    idun_device_monitor_start_finish(self->m_monitor, res, &error);
    if (error != nullptr) {
        self->fail(QString::fromUtf8(error->message));
        g_error_free(error);
    }
}

void IdunScreen::onDeviceAttached(IdunDeviceMonitor *monitor, IdunDevice *device, IdunScreen *self)
{
    if (!self->m_udid.isEmpty() && self->m_udid != QString::fromUtf8(idun_device_get_udid(device)))
        return;

    g_signal_handlers_disconnect_by_func(monitor, reinterpret_cast<gpointer>(onDeviceAttached), self);

    auto ctx = new OpenCtx { self, static_cast<IdunDevice *>(g_object_ref(device)), nullptr };
    idun_display_stream_open(device, nullptr, onStreamOpened, ctx);
}

void IdunScreen::onStreamOpened(GObject *sourceObject, GAsyncResult *res, gpointer userData)
{
    auto ctx = static_cast<OpenCtx *>(userData);
    GError *error = nullptr;

    ctx->stream = idun_display_stream_open_finish(res, &error);
    if (error != nullptr) {
        ctx->self->fail(QString::fromUtf8(error->message));
        g_object_unref(ctx->device);
        g_error_free(error);
        delete ctx;
        return;
    }

    idun_hid_client_open(ctx->device, nullptr, onHidOpened, ctx);
}

void IdunScreen::onHidOpened(GObject *sourceObject, GAsyncResult *res, gpointer userData)
{
    auto ctx = static_cast<OpenCtx *>(userData);
    GError *error = nullptr;

    auto hid = idun_hid_client_open_finish(res, &error);
    if (error != nullptr) {
        ctx->self->fail(QString::fromUtf8(error->message));
        g_object_unref(ctx->stream);
        g_object_unref(ctx->device);
        g_error_free(error);
        delete ctx;
        return;
    }

    ctx->self->onStreamReady(ctx->stream, hid);

    g_object_unref(ctx->device);
    delete ctx;
}

void IdunScreen::onStreamReady(IdunDisplayStream *stream, IdunHidClient *hid)
{
    m_hid = hid;

    QMetaObject::invokeMethod(this, [this, stream]() {
        m_deviceWidth = idun_display_stream_get_width(stream);
        m_deviceHeight = idun_display_stream_get_height(stream);
        Q_EMIT deviceSizeChanged();

        bool built = buildPipeline(stream);
        g_object_unref(stream);
        if (built)
            Q_EMIT streaming();
    }, Qt::QueuedConnection);
}

bool IdunScreen::buildPipeline(IdunDisplayStream *stream)
{
    for (auto name : pipelineElements) {
        auto factory = gst_element_factory_find(name);
        if (factory == nullptr) {
            Q_EMIT failed(QStringLiteral("Missing GStreamer element: %1").arg(QLatin1String(name)));
            return false;
        }
        gst_object_unref(factory);
    }

    m_videoItem = createVideoOutput();
    if (m_videoItem == nullptr)
        return false;
    m_videoItem->setParentItem(this);
    m_videoItem->setSize(QSizeF(width(), height()));

    m_pipeline = gst_pipeline_new("idun-screen");
    auto src = gst_element_factory_make("idunscreensrc", "src");
    auto parser = gst_element_factory_make("h264parse", "parser");
    auto decoder = gst_element_factory_make("decodebin3", "decoder");
    m_convert = gst_element_factory_make("videoconvert", "convert");
    auto sink = gst_element_factory_make("appsink", "sink");

    g_object_set(src, "stream", stream, nullptr);
    auto caps = gst_caps_new_simple("video/x-raw", "format", G_TYPE_STRING, "I420", nullptr);
    g_object_set(sink, "caps", caps, "emit-signals", TRUE, "max-buffers", 1, "drop", TRUE, "sync", FALSE, nullptr);
    gst_caps_unref(caps);

    gst_bin_add_many(GST_BIN(m_pipeline), src, parser, decoder, m_convert, sink, nullptr);
    gst_element_link_many(src, parser, decoder, nullptr);
    gst_element_link(m_convert, sink);
    g_signal_connect(decoder, "pad-added", G_CALLBACK(onDecoderPadAdded), this);
    g_signal_connect(sink, "new-sample", G_CALLBACK(onNewSample), this);

    auto bus = gst_element_get_bus(m_pipeline);
    gst_bus_set_sync_handler(bus, onBusMessage, this, nullptr);
    gst_object_unref(bus);

    gst_element_set_state(m_pipeline, GST_STATE_PLAYING);

    return true;
}

QQuickItem *IdunScreen::createVideoOutput()
{
    QQmlComponent component(qmlEngine(this));
    component.setData("import QtMultimedia\nVideoOutput { fillMode: VideoOutput.Stretch }", QUrl());
    auto item = qobject_cast<QQuickItem *>(component.create());
    if (item == nullptr) {
        Q_EMIT failed(component.errorString().trimmed());
        return nullptr;
    }
    m_videoSink = item->property("videoSink").value<QVideoSink *>();
    return item;
}

GstFlowReturn IdunScreen::onNewSample(GstElement *sink, IdunScreen *self)
{
    auto sample = gst_app_sink_pull_sample(GST_APP_SINK(sink));
    if (sample == nullptr)
        return GST_FLOW_FLUSHING;
    self->pushFrame(sample);
    gst_sample_unref(sample);
    return GST_FLOW_OK;
}

void IdunScreen::pushFrame(GstSample *sample)
{
    GstVideoInfo info;
    gst_video_info_from_caps(&info, gst_sample_get_caps(sample));

    GstVideoFrame source;
    if (!gst_video_frame_map(&source, &info, gst_sample_get_buffer(sample), GST_MAP_READ))
        return;

    QVideoFrame frame(QVideoFrameFormat(QSize(info.width, info.height), QVideoFrameFormat::Format_YUV420P));
    frame.map(QVideoFrame::WriteOnly);
    for (int plane = 0; plane != 3; plane++) {
        auto src = static_cast<const uchar *>(GST_VIDEO_FRAME_PLANE_DATA(&source, plane));
        auto srcStride = GST_VIDEO_FRAME_PLANE_STRIDE(&source, plane);
        auto dst = frame.bits(plane);
        auto dstStride = frame.bytesPerLine(plane);
        auto rowBytes = qMin(srcStride, dstStride);
        auto rows = GST_VIDEO_FRAME_COMP_HEIGHT(&source, plane);
        for (int row = 0; row != rows; row++)
            memcpy(dst + row * dstStride, src + row * srcStride, rowBytes);
    }
    frame.unmap();
    gst_video_frame_unmap(&source);

    QMetaObject::invokeMethod(this, [this, frame]() {
        m_videoSink->setVideoFrame(frame);
    }, Qt::QueuedConnection);
}

void IdunScreen::onDecoderPadAdded(GstElement *decoder, GstPad *pad, IdunScreen *self)
{
    auto sink = gst_element_get_static_pad(self->m_convert, "sink");
    if (!gst_pad_is_linked(sink))
        gst_pad_link(pad, sink);
    gst_object_unref(sink);
}

GstBusSyncReply IdunScreen::onBusMessage(GstBus *bus, GstMessage *message, gpointer userData)
{
    if (GST_MESSAGE_TYPE(message) == GST_MESSAGE_ERROR) {
        GError *error = nullptr;
        gst_message_parse_error(message, &error, nullptr);
        static_cast<IdunScreen *>(userData)->fail(QString::fromUtf8(error->message));
        g_error_free(error);
    }
    return GST_BUS_PASS;
}

void IdunScreen::geometryChange(const QRectF &newGeometry, const QRectF &oldGeometry)
{
    QQuickItem::geometryChange(newGeometry, oldGeometry);
    if (m_videoItem != nullptr)
        m_videoItem->setSize(newGeometry.size());
}

void IdunScreen::mousePressEvent(QMouseEvent *event)
{
    dispatchTouch(idun_hid_client_touch_down, event->position().x(), event->position().y());
}

void IdunScreen::mouseMoveEvent(QMouseEvent *event)
{
    dispatchTouch(idun_hid_client_touch_move, event->position().x(), event->position().y());
}

void IdunScreen::mouseReleaseEvent(QMouseEvent *event)
{
    dispatchTouch(idun_hid_client_touch_up, event->position().x(), event->position().y());
}

void IdunScreen::dispatchTouch(void (*fn)(IdunHidClient *, double, double, IdunDigitizerEdge), double x, double y)
{
    if (m_hid == nullptr || width() <= 0 || height() <= 0)
        return;

    double nx = qBound(0.0, x / width(), 1.0);
    double ny = qBound(0.0, y / height(), 1.0);
    IdunHidClient *hid = m_hid;

    invokeOnWorker([fn, hid, nx, ny]() {
        fn(hid, nx, ny, IDUN_DIGITIZER_EDGE_NONE);
    });
}

void IdunScreen::invokeOnWorker(std::function<void ()> fn)
{
    g_main_context_invoke_full(m_context, G_PRIORITY_DEFAULT, invokeCpp, new std::function<void ()>(std::move(fn)), destroyCpp);
}

void IdunScreen::fail(const QString &message)
{
    QMetaObject::invokeMethod(this, [this, message]() {
        Q_EMIT failed(message);
    }, Qt::QueuedConnection);
}
