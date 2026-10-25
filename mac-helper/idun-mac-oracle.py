#!/usr/bin/env python3

import argparse
import base64
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import frida

AGENT = Path(__file__).parent / "idun-mac-agent.js"
HOST = Path(__file__).parent / "idun-mac-host.py"
PYTHON = "/usr/bin/python3"
AKD = "/System/Library/PrivateFrameworks/AuthKit.framework/Versions/A/Support/akd"
IDS = "identityservicesd"


def main():
    parser = argparse.ArgumentParser(description="Serve Apple identity primitives to a Linux Idun client.")
    parser.add_argument("--listen", default="127.0.0.1:8080", help="address to serve on (default: %(default)s)")
    parser.add_argument("--frida-server", default="127.0.0.1:27043",
                        help="patched frida-server for the daemon host (default: %(default)s)")
    parser.add_argument("--akd-frida-server", default="127.0.0.1:27042",
                        help="signed frida-server able to inject akd for anisette (default: %(default)s)")
    args = parser.parse_args()

    oracle = Oracle(args.frida_server, args.akd_frida_server)
    oracle.start()

    host, port = args.listen.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port)), make_handler(oracle))
    print(f"serving on {args.listen}", file=sys.stderr, flush=True)
    server.serve_forever()


class Oracle:
    def __init__(self, frida_server, akd_frida_server):
        self._frida_server = frida_server
        self._akd_frida_server = akd_frida_server
        self._agent = AGENT.read_text()
        self._validation_lock = threading.Lock()
        self._akd_lock = threading.Lock()
        self._ids_lock = threading.Lock()
        self._host_process = None
        self._host = None
        self._akd = None
        self._ids = None

    def start(self):
        device = frida.get_device_manager().add_remote_device(self._frida_server)
        self._host_process = subprocess.Popen([PYTHON, "-I", str(HOST)], stdout=subprocess.PIPE)
        self._host_process.stdout.readline()
        self._host = self._load(device, self._host_process.pid)

    def _load(self, device, pid):
        script = device.attach(pid).create_script(self._agent)
        script.load()
        return script

    def anisette(self):
        with self._akd_lock:
            return self._ensure_akd().exports_sync.anisette()

    def baa_headers(self):
        with self._akd_lock:
            return self._ensure_akd().exports_sync.baa_headers()

    def _ensure_akd(self):
        if self._akd is None:
            device = frida.get_device_manager().add_remote_device(self._akd_frida_server)
            akd = next(p for p in device.enumerate_processes(scope="full")
                       if p.parameters.get("path", "").endswith(AKD) and p.parameters.get("user") != "root")
            self._akd = self._load(device, akd.pid)
        return self._akd

    def absinthe(self, request):
        with self._ids_lock:
            return self._ensure_ids().exports_sync.absinthe_headers(request["digest"], request["body"])

    def _ensure_ids(self):
        if self._ids is None:
            device = frida.get_device_manager().add_remote_device(self._akd_frida_server)
            ids = next(p for p in device.enumerate_processes(scope="full")
                       if p.name == IDS and p.parameters.get("user") != "root")
            self._ids = self._load(device, ids.pid)
        return self._ids

    def device_info(self):
        return self._host.exports_sync.device_info()

    def fairplay_sign(self, body):
        return self._host.exports_sync.fairplay_sign(base64.b64encode(body).decode())

    def validation_begin(self):
        with self._validation_lock:
            return self._host.exports_sync.validation_begin()

    def validation_continue(self, request):
        with self._validation_lock:
            return self._host.exports_sync.validation_continue(request["status"], request["body"])


def make_handler(oracle):
    get_routes = {
        "/anisette": lambda body: oracle.anisette(),
        "/baa-headers": lambda body: oracle.baa_headers(),
        "/device-info": lambda body: oracle.device_info(),
    }
    post_routes = {
        "/fairplay-sign": lambda body: oracle.fairplay_sign(body),
        "/absinthe": lambda body: oracle.absinthe(json.loads(body)),
        "/validation/begin": lambda body: oracle.validation_begin(),
        "/validation/continue": lambda body: oracle.validation_continue(json.loads(body)),
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self._dispatch(get_routes, b"")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self._dispatch(post_routes, self.rfile.read(length))

        def _dispatch(self, routes, body):
            route = routes.get(self.path)
            if route is None:
                self._reply(404, {"error": "not found"})
                return
            try:
                self._reply(200, route(body))
            except Exception as e:
                self._reply(500, {"error": str(e)})

        def _reply(self, status, payload):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    return Handler


if __name__ == "__main__":
    main()
