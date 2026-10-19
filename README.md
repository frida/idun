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

A device only allows one CoreDevice tunnel per host, so on Linux
the tunnel lives in idund, a per-user daemon, and every process
on the desktop shares it. Clients reach it through the session
bus, where a packaged install provides D-Bus activation and a
systemd user unit, or over peer-to-peer D-Bus on a Unix socket in
the user's runtime directory. Tunnel connections are handed over
as socket pairs. A client that finds no daemon starts one from
the installed location next to the library, or from a path the
application supplies, and the daemon exits once it has been idle
for a while. On macOS the system's own tunnel is used instead;
Windows support for the daemon is still to come.

When idund may create TUN interfaces on Linux, which takes
CAP_NET_ADMIN, the tunnel becomes a kernel network interface and
clients talk to the device through ordinary sockets. Grant it with
`setcap cap_net_admin+ep idund` on an installed daemon. Without it,
and always on Windows, the tunnel runs on a userspace network stack
inside the daemon, which relays connections to its clients as socket
pairs.

## Building

```sh
./configure
make
```

[Efni]: https://github.com/frida/efni
