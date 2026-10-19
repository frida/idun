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

Frida's Apple backend is built on this library. A per-user
daemon, idund, is planned for Windows and Linux so that one
CoreDevice tunnel can be shared by every process on the
desktop; on macOS the system's own tunnel is used.

## Building

```sh
./configure
make
```

[Efni]: https://github.com/frida/efni
