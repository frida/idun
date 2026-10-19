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
on the desktop shares it. Clients connect to it over peer-to-peer
D-Bus on a Unix socket in the user's runtime directory, and
tunnel connections are handed over as socket pairs. A client that
finds no daemon starts one, and the daemon exits once it has been
idle for a while. Without an idund binary, the library opens the
tunnel in-process, so nothing requires the daemon. Set
`IDUN_DAEMON=never` to force in-process tunnels. On macOS the
system's own tunnel is used instead; Windows support for the
daemon is still to come.

## Building

```sh
./configure
make
```

[Efni]: https://github.com/frida/efni
