# Reticulum License
#
# Copyright (c) 2026 Florian
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# - The Software shall not be used in any kind of system which includes amongst
#   its functions the ability to purposefully do harm to human beings.
#
# - The Software shall not be used, directly or indirectly, in the creation of
#   an artificial intelligence, machine learning or language model training
#   dataset, including but not limited to any use that contributes to the
#   training or development of such a model or algorithm.
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Reticulum transport over the official Meshtastic command-line client.

Meshtastic's CLI exposes text messages, rather than a generic raw-payload
command. This interface therefore carries RNS packets in a small, URL-safe
base64 text envelope. It deliberately does not import the Meshtastic Python
library; device discovery, connection and radio transport remain the CLI's
responsibility.
"""

import base64
import binascii
import os
import queue
import re
import shlex
import subprocess
import threading
import time

import RNS
from RNS.Interfaces.Interface import Interface


class MeshtasticFrameCodec:
    """Encode RNS packets into text messages that fit Meshtastic payloads."""

    PREFIX = "RNSMT1"
    HEADER_RE = re.compile(
        r"^RNSMT1:([0-9a-f]{8}):([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{8}):([A-Za-z0-9_-]*)$"
    )

    @staticmethod
    def encode(data, text_limit=200):
        if not isinstance(data, bytes):
            raise TypeError("Meshtastic frames can only encode bytes")
        if text_limit < 48:
            raise ValueError("message_size must be at least 48 characters")

        transfer_id = os.urandom(4).hex()
        checksum = f"{binascii.crc32(data) & 0xffffffff:08x}"
        # Fixed header is 31 characters. Base64 expands in groups of four.
        raw_chunk_size = max(1, ((text_limit - 31) // 4) * 3)
        chunks = [data[offset:offset + raw_chunk_size] for offset in range(0, len(data), raw_chunk_size)] or [b""]
        if len(chunks) > 255:
            raise ValueError("Packet requires too many Meshtastic fragments")

        return [
            f"{MeshtasticFrameCodec.PREFIX}:{transfer_id}:{index:02x}:{len(chunks):02x}:{checksum}:"
            + base64.urlsafe_b64encode(chunk).decode("ascii").rstrip("=")
            for index, chunk in enumerate(chunks)
        ]

    @staticmethod
    def decode(frame):
        match = MeshtasticFrameCodec.HEADER_RE.match(frame)
        if not match:
            return None
        transfer_id, index, count, checksum, encoded = match.groups()
        try:
            payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        except (ValueError, binascii.Error):
            return None
        index, count = int(index, 16), int(count, 16)
        if count == 0 or index >= count:
            return None
        return transfer_id, index, count, checksum, payload


class MeshtasticInterface(Interface):
    """A bidirectional RNS interface backed by the ``meshtastic`` CLI."""

    DEFAULT_MESSAGE_SIZE = 200
    DEFAULT_BITRATE = 118
    DEFAULT_REASSEMBLY_TIMEOUT = 300
    MAX_REASSEMBLIES = 64
    TEXT_RE = re.compile(r"(?:['\"]text['\"]\s*:\s*['\"]|^)(RNSMT1:[A-Za-z0-9:_-]+)")

    def __init__(self, owner, configuration):
        super().__init__()
        c = Interface.get_config_obj(configuration)
        self.owner = owner
        self.name = c["name"]
        self.cli_command = c["cli_command"] if "cli_command" in c else "meshtastic"
        self.channel = c.as_int("channel") if "channel" in c else 0
        self.destination = c["destination"] if "destination" in c else None
        self.message_size = c.as_int("message_size") if "message_size" in c else self.DEFAULT_MESSAGE_SIZE
        self.reassembly_timeout = c.as_float("reassembly_timeout") if "reassembly_timeout" in c else self.DEFAULT_REASSEMBLY_TIMEOUT
        self.listen = c.as_bool("listen") if "listen" in c else True
        self.connection_args = self._connection_args(c)
        self.extra_args = c.as_list("cli_args") if "cli_args" in c else []
        self.bitrate = c.as_int("bitrate") if "bitrate" in c else self.DEFAULT_BITRATE
        self.HW_MTU = 500
        self.online = False
        self.detached = False
        self.listener = None
        self.fragments = {}
        self.fragments_lock = threading.Lock()
        self.send_queue = queue.Queue()

        if not shlex.split(self.cli_command):
            raise ValueError("cli_command must not be empty")

        self._send_thread = threading.Thread(target=self._send_loop, name=f"Meshtastic send {self.name}", daemon=True)
        self._send_thread.start()
        if self.listen:
            self._start_listener()
        else:
            self.online = True
        RNS.log(f"Meshtastic CLI interface {self} is ready", RNS.LOG_NOTICE)

    @staticmethod
    def _connection_args(c):
        options = [("port", "--port"), ("host", "--host"), ("ble", "--ble")]
        configured = [(key, option) for key, option in options if key in c and c[key]]
        if len(configured) > 1:
            raise ValueError("Specify only one of port, host or ble")
        return [configured[0][1], str(c[configured[0][0]])] if configured else []

    def _command(self, *args):
        return shlex.split(self.cli_command) + self.connection_args + self.extra_args + list(args)

    def _start_listener(self):
        if self.detached:
            return
        try:
            command = self._command("--listen", "--no-time", "--no-nodes")
            RNS.log(f"Starting Meshtastic CLI listener for {self}", RNS.LOG_VERBOSE)
            self.listener = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            self.online = True
            for stream in (self.listener.stdout, self.listener.stderr):
                threading.Thread(target=self._read_listener, args=(stream,), daemon=True).start()
            threading.Thread(target=self._watch_listener, daemon=True).start()
        except Exception as error:
            self.online = False
            RNS.log(f"Could not start Meshtastic CLI listener for {self}: {error}", RNS.LOG_ERROR)

    def _watch_listener(self):
        if self.listener is not None:
            self.listener.wait()
        if not self.detached:
            self.online = False
            RNS.log(f"Meshtastic CLI listener for {self} exited; retrying in 5 seconds", RNS.LOG_WARNING)
            time.sleep(5)
            self._start_listener()

    def _read_listener(self, stream):
        try:
            for line in iter(stream.readline, ""):
                self._process_cli_line(line)
        except Exception as error:
            if not self.detached:
                RNS.log(f"Error reading Meshtastic CLI output for {self}: {error}", RNS.LOG_ERROR)

    def _process_cli_line(self, line):
        # --listen enables DEBUG output in the official CLI. It contains
        # "Publishing meshtastic.receive.text: packet=... 'text': '...'."
        # Also accept JSON-style output for CLI versions that emit it directly.
        match = self.TEXT_RE.search(line)
        if match:
            self._process_frame(match.group(1))

    def _process_frame(self, frame):
        decoded = MeshtasticFrameCodec.decode(frame)
        if decoded is None:
            return
        transfer_id, index, count, checksum, payload = decoded
        key = (transfer_id, count, checksum)
        now = time.monotonic()
        with self.fragments_lock:
            self._expire_fragments(now)
            entry = self.fragments.setdefault(key, {"created": now, "parts": {}})
            entry["parts"][index] = payload
            if len(entry["parts"]) != count:
                return
            data = b"".join(entry["parts"][part] for part in range(count))
            self.fragments.pop(key, None)
        if f"{binascii.crc32(data) & 0xffffffff:08x}" != checksum:
            RNS.log(f"Discarding corrupt Meshtastic transfer on {self}", RNS.LOG_WARNING)
            return
        self.rxb += len(data)
        self.owner.inbound(data, self)

    def _expire_fragments(self, now):
        expired = [key for key, value in self.fragments.items() if now - value["created"] > self.reassembly_timeout]
        for key in expired:
            self.fragments.pop(key, None)
        while len(self.fragments) >= self.MAX_REASSEMBLIES:
            self.fragments.pop(next(iter(self.fragments)))

    def process_incoming(self, data):
        """Accept a frame in tests or from a custom CLI output adapter."""
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="ignore")
        self._process_frame(data)

    def process_outgoing(self, data):
        if self.detached:
            return
        try:
            for frame in MeshtasticFrameCodec.encode(data, self.message_size):
                self.send_queue.put(frame)
        except Exception as error:
            RNS.log(f"Could not prepare packet for {self}: {error}", RNS.LOG_ERROR)

    def _send_loop(self):
        while not self.detached:
            try:
                frame = self.send_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            command = self._command("--ch-index", str(self.channel), "--sendtext", frame, "--wait-to-disconnect", "0")
            if self.destination:
                command.extend(["--dest", self.destination])
            try:
                result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
                if result.returncode != 0:
                    RNS.log(f"Meshtastic CLI send failed on {self}: {result.stderr.strip() or result.stdout.strip()}", RNS.LOG_ERROR)
                else:
                    self.txb += len(frame)
            except Exception as error:
                RNS.log(f"Meshtastic CLI send failed on {self}: {error}", RNS.LOG_ERROR)
            finally:
                self.send_queue.task_done()

    def detach(self):
        self.detached = True
        self.online = False
        if self.listener is not None and self.listener.poll() is None:
            self.listener.terminate()

    def __str__(self):
        return f"MeshtasticInterface[{self.name}]"


# Makes the module usable as an external interface module too.
interface_class = MeshtasticInterface
