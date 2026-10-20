# Idun

Library for talking to Apple devices from Windows, macOS and
Linux, written in Vala on top of [Efni][].

Idun (Old Norse Iðunn, keeper of the apples) covers:

- Device discovery over USB and the network, via usbmuxd,
  libusb with NCM, and mDNS.
- Pairing, lockdown, and the CoreDevice tunnel, including
  an in-process tunnel implementation for systems without a
  daemon.
- Service clients: installation proxy, SpringBoard
  services, DTX instruments, RemoteXPC, and LLDB.
- Codecs: property lists, keyed archives, OPACK, kcdata,
  kdebug, and kperfdata.

Frida's Apple backend is built on this library.

## idund

A device only allows one CoreDevice tunnel per host, so on Windows
and Linux the tunnel lives in idund, a per-user daemon, and every
process on the desktop shares it. On Linux clients reach it through
the session bus, where a packaged install provides D-Bus activation
and a systemd user unit, or over peer-to-peer D-Bus on a Unix socket
in the user's runtime directory. On Windows the daemon listens on
loopback and records its address in a control file under the user's
local application data. A client that finds no daemon starts one
from the installed location next to the library, or from a path the
application supplies, and the daemon exits once it has been idle for
a while. On macOS the system's own tunnel is used instead.

When idund may create TUN interfaces on Linux, which takes
CAP_NET_ADMIN, the tunnel becomes a kernel network interface and
clients talk to the device through ordinary sockets. Grant it with
`setcap cap_net_admin+ep idund` on an installed daemon. Without it,
and always on Windows, the tunnel runs on a userspace network stack
inside the daemon, which relays connections to its clients as socket
pairs.

## Device services

Beyond the device and tunnel plumbing, Idun exposes the CoreDevice
services a desktop integration needs: `PasteboardService` (read, write,
and change notifications for the device clipboard), `ScreenCaptureService`
(pull a PNG screenshot), `CoreDeviceInfoService` (display geometry),
`HidClient` (inject touches and the Home gesture), and `DisplayStream`
(a live H.264 screen feed). The `coredevice-demo` example under
`examples/` drives all of them.

## Screen mirroring

`DisplayStream` negotiates the CoreDevice display service and hands the
raw RTP/RTCP datagrams to GStreamer, which owns the whole RTP stack. The
`idunscreensrc` element (built when GStreamer is present) wraps a
`DisplayStream` and produces depayloaded H.264:

```sh
gst-launch-1.0 idunscreensrc ! h264parse ! decodebin3 ! autovideosink
```

For an embeddable, toolkit-agnostic view, the GStreamer element feeds the
renderer the UI toolkit provides: `gtk4paintablesink` for a GTK widget,
or the in-process Quickshell/Qt module. The module (built when Qt 6 and
the GStreamer Qt 6 sink are present) installs a QML type:

```qml
import Idun.Screen

IdunScreen {
    anchors.fill: parent
    udid: "00008150-001C10660E08401C"
}
```

The item renders the device's screen through `qml6glsink` and turns
pointer events into touches. The GStreamer element and the Quickshell
module link the system GStreamer and Qt, so they are built against
system libraries rather than the bundled SDK.

## Building

```sh
./configure
make
```

[Efni]: https://github.com/frida/efni
