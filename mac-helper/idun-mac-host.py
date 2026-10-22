#!/usr/bin/env python3

import ctypes
import sys

DAEMONS = [
    "/System/Library/Frameworks/CFNetwork.framework/CFNetwork",
    "/System/Library/PrivateFrameworks/ApplePushService.framework/apsd",
    "/System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd",
]


def main():
    for daemon in DAEMONS:
        ctypes.CDLL(daemon, mode=ctypes.RTLD_GLOBAL)

    print("ready", flush=True)

    core_foundation = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    core_foundation.CFRunLoopRun()


if __name__ == "__main__":
    sys.exit(main())
