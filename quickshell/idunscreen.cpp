#include "idunscreen.h"

#include <QMouseEvent>
#include <functional>

namespace {

struct OpenCtx
{
    IdunScreen *self;
    IdunDevice *device;
    IdunDisplayStream *stream;
};

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
    idun_device_monitor_start(self->m_monitor, nullptr, nullptr, nullptr);

    g_main_loop_run(self->m_loop);

    g_main_context_pop_thread_default(self->m_context);
    return nullptr;
}

void IdunScreen::onDeviceAttached(IdunDeviceMonitor *monitor, IdunDevice *device, IdunScreen *self)
{
    if (self->m_hid != nullptr)
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
    g_object_get(stream, "width", &m_deviceWidth, "height", &m_deviceHeight, nullptr);

    QMetaObject::invokeMethod(this, [this, stream]() {
        buildPipeline(stream);
        g_object_unref(stream);
        Q_EMIT streaming();
    }, Qt::QueuedConnection);
}

void IdunScreen::buildPipeline(IdunDisplayStream *stream)
{
    m_pipeline = gst_pipeline_new("idun-screen");
    auto src = gst_element_factory_make("idunscreensrc", "src");
    auto parser = gst_element_factory_make("h264parse", "parser");
    auto decoder = gst_element_factory_make("decodebin3", "decoder");
    m_upload = gst_element_factory_make("glupload", "upload");
    auto sink = gst_element_factory_make("qml6glsink", "sink");

    g_object_set(src, "stream", stream, nullptr);

    gst_bin_add_many(GST_BIN(m_pipeline), src, parser, decoder, m_upload, sink, nullptr);
    gst_element_link_many(src, parser, decoder, nullptr);
    gst_element_link(m_upload, sink);
    g_signal_connect(decoder, "pad-added", G_CALLBACK(onDecoderPadAdded), this);

    gpointer widget = nullptr;
    g_object_get(sink, "widget", &widget, nullptr);
    m_videoItem = static_cast<QQuickItem *>(widget);
    m_videoItem->setParentItem(this);
    m_videoItem->setSize(QSizeF(width(), height()));

    gst_element_set_state(m_pipeline, GST_STATE_PLAYING);
}

void IdunScreen::onDecoderPadAdded(GstElement *decoder, GstPad *pad, IdunScreen *self)
{
    auto sink = gst_element_get_static_pad(self->m_upload, "sink");
    if (!gst_pad_is_linked(sink))
        gst_pad_link(pad, sink);
    gst_object_unref(sink);
}

void IdunScreen::geometryChange(const QRectF &newGeometry, const QRectF &oldGeometry)
{
    QQuickItem::geometryChange(newGeometry, oldGeometry);
    if (m_videoItem != nullptr)
        m_videoItem->setSize(newGeometry.size());
}

void IdunScreen::mousePressEvent(QMouseEvent *event)
{
    dispatchTouch([](IdunHidClient *hid, double x, double y, int edge) {
        idun_hid_client_touch_down(hid, x, y, static_cast<IdunDigitizerEdge>(edge));
    }, event->position().x(), event->position().y());
}

void IdunScreen::mouseMoveEvent(QMouseEvent *event)
{
    dispatchTouch([](IdunHidClient *hid, double x, double y, int edge) {
        idun_hid_client_touch_move(hid, x, y, static_cast<IdunDigitizerEdge>(edge));
    }, event->position().x(), event->position().y());
}

void IdunScreen::mouseReleaseEvent(QMouseEvent *event)
{
    dispatchTouch([](IdunHidClient *hid, double x, double y, int edge) {
        idun_hid_client_touch_up(hid, x, y, static_cast<IdunDigitizerEdge>(edge));
    }, event->position().x(), event->position().y());
}

void IdunScreen::dispatchTouch(void (*fn)(IdunHidClient *, double, double, int), double x, double y)
{
    if (m_hid == nullptr || width() <= 0 || height() <= 0)
        return;

    double nx = qBound(0.0, x / width(), 1.0);
    double ny = qBound(0.0, y / height(), 1.0);
    IdunHidClient *hid = m_hid;

    auto work = new std::function<void ()>([fn, hid, nx, ny]() {
        fn(hid, nx, ny, 0);
    });
    g_main_context_invoke_full(m_context, G_PRIORITY_DEFAULT, invokeCpp, work, destroyCpp);
}
