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

## Distro Packaging

For building a shared library suitable for distro packaging:

```console
$ ./configure --enable-shared --without-prebuilds=sdk && make
```

This builds `libidun-1.0.so`, `idund`, the `idunscreensrc` GStreamer
element and the `Idun.Screen` Quickshell module against system
dependencies, including a system-installed Efni, using Frida's
toolchain for the Vala compiler. lwIP has no distro package, so it is
built from its wrap and linked statically.

Prerequisites on Omarchy / Arch Linux:

```console
$ sudo pacman -S --needed efni glib2 libgee json-glib libnghttp2 \
      openssl libngtcp2 libusb gstreamer gst-plugins-base-libs \
      qt6-declarative libgirepository
```

Prerequisites on Fedora:

```console
$ sudo dnf install efni-devel glib2-devel libgee-devel json-glib-devel \
      libnghttp2-devel openssl-devel ngtcp2-devel \
      ngtcp2-crypto-ossl-devel libusb1-devel gstreamer1-devel \
      gstreamer1-plugins-base-devel qt6-qtdeclarative-devel \
      gobject-introspection-devel
```

Prerequisites on Ubuntu:

```console
$ sudo apt install libefni-dev libglib2.0-dev libgee-0.8-dev \
      libjson-glib-dev libnghttp2-dev libssl-dev libngtcp2-dev \
      libngtcp2-crypto-ossl-dev libusb-1.0-0-dev libgstreamer1.0-dev \
      libgstreamer-plugins-base1.0-dev qt6-declarative-dev \
      libgirepository1.0-dev
```

Recipes for Arch (`PKGBUILD`), Fedora (`.spec`) and Debian/Ubuntu
(`debian/`) live in `packaging/`. The Fedora and Debian builds run
without network access, so they take Frida's toolchain as an
additional source, and expect a source tarball that includes the
`releng` submodule and the lwIP wrap source under `subprojects/`.
