# Reticulum License
#
# Copyright (c) 2026 flopetautschnig (floscodes)
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

"""Reticulum transport over Meshtastic's native binary data API."""

import binascii
import os
import threading
import time

import RNS
from RNS.Interfaces.Interface import Interface


class MeshtasticFrameCodec:
    """Fragment RNS packets into Meshtastic binary payloads.

    Meshtastic limits an application payload to 233 bytes. The header keeps
    fragment reassembly internal to this interface and never turns binary RNS
    traffic into text.
    """

    MAGIC = b"RNSM"
    VERSION = 1
    HEADER_SIZE = 15

    @classmethod
    def encode(cls, data, payload_size):
        if not isinstance(data, bytes):
            raise TypeError("Meshtastic frames can only encode bytes")
        chunk_size = payload_size - cls.HEADER_SIZE
        if chunk_size < 1:
            raise ValueError(f"payload_size must be at least {cls.HEADER_SIZE + 1} bytes")

        chunks = [data[offset:offset + chunk_size] for offset in range(0, len(data), chunk_size)] or [b""]
        if len(chunks) > 255:
            raise ValueError("Packet requires too many Meshtastic fragments")

        transfer_id = os.urandom(4)
        checksum = binascii.crc32(data).to_bytes(4, "big")
        return [
            cls.MAGIC + bytes([cls.VERSION]) + transfer_id + bytes([index, len(chunks)]) + checksum + chunk
            for index, chunk in enumerate(chunks)
        ]

    @classmethod
    def decode(cls, frame):
        if not isinstance(frame, bytes) or len(frame) < cls.HEADER_SIZE:
            return None
        if frame[:4] != cls.MAGIC or frame[4] != cls.VERSION:
            return None

        transfer_id = frame[5:9]
        index, count = frame[9], frame[10]
        if count == 0 or index >= count:
            return None
        return transfer_id, index, count, frame[11:15], frame[15:]


class MeshtasticInterface(Interface):
    """A bidirectional binary Reticulum interface over Meshtastic."""

    DEFAULT_IFAC_SIZE = 8
    DEFAULT_BITRATE = 118
    DEFAULT_PAYLOAD_SIZE = 233
    DEFAULT_REASSEMBLY_TIMEOUT = 300
    MAX_REASSEMBLIES = 64

    def __init__(self, owner, configuration):
        super().__init__()
        c = Interface.get_config_obj(configuration)
        self.owner = owner
        self.name = c["name"]
        self.channel = c.as_int("channel") if "channel" in c else 0
        self.destination = c["destination"] if "destination" in c else "^all"
        self.payload_size = c.as_int("payload_size") if "payload_size" in c else self.DEFAULT_PAYLOAD_SIZE
        self.reassembly_timeout = c.as_float("reassembly_timeout") if "reassembly_timeout" in c else self.DEFAULT_REASSEMBLY_TIMEOUT
        self.connection_timeout = c.as_int("connection_timeout") if "connection_timeout" in c else 30
        self.want_ack = c.as_bool("want_ack") if "want_ack" in c else False
        self.hop_limit = c.as_int("hop_limit") if "hop_limit" in c else None
        self.bitrate = c.as_int("bitrate") if "bitrate" in c else self.DEFAULT_BITRATE
        self.HW_MTU = 500
        # Reticulum only forwards outbound packets to interfaces explicitly
        # marked as outgoing. This interface carries traffic in both directions.
        self.IN = True
        self.OUT = True
        self.online = False
        self.detached = False
        self.fragments = {}
        self.fragments_lock = threading.Lock()
        self.send_lock = threading.Lock()

        self.port, self.host, self.ble = self._connection_config(c)
        self._load_meshtastic()
        self.mesh_interface = self._connect()
        self.pub.subscribe(self._on_receive, "meshtastic.receive")
        self.pub.subscribe(self._on_connection_lost, "meshtastic.connection.lost")
        self.online = self.mesh_interface.isConnected.is_set()
        RNS.log(f"Meshtastic binary interface {self} is ready", RNS.LOG_NOTICE)

    @staticmethod
    def _connection_config(c):
        configured = [name for name in ("port", "host", "ble") if name in c and c[name]]
        if len(configured) > 1:
            raise ValueError("Specify only one of port, host or ble")
        return (
            c["port"] if "port" in configured else None,
            c["host"] if "host" in configured else None,
            c["ble"] if "ble" in configured else None,
        )

    def _load_meshtastic(self):
        try:
            from pubsub import pub
            from meshtastic.protobuf import portnums_pb2
            from meshtastic.serial_interface import SerialInterface
            from meshtastic.tcp_interface import TCPInterface
            from meshtastic.ble_interface import BLEInterface
        except ImportError as error:
            raise ImportError(
                "MeshtasticInterface requires the meshtastic package. "
                "Install Reticulum with the meshtastic extra."
            ) from error

        self.pub = pub
        self.port_num = portnums_pb2.PortNum.RETICULUM_TUNNEL_APP
        self.SerialInterface = SerialInterface
        self.TCPInterface = TCPInterface
        self.BLEInterface = BLEInterface

    def _connect(self):
        options = {"noNodes": True, "timeout": self.connection_timeout}
        if self.port:
            return self.SerialInterface(devPath=self.port, **options)
        if self.host:
            return self.TCPInterface(hostname=self.host, **options)
        if self.ble:
            return self.BLEInterface(address=self.ble, **options)
        return self.SerialInterface(**options)

    def _on_receive(self, packet, interface):
        if interface is not self.mesh_interface:
            return
        decoded = packet.get("decoded", {})
        port_num = decoded.get("portnum")
        if port_num not in (self.port_num, "RETICULUM_TUNNEL_APP"):
            return
        payload = decoded.get("payload")
        if isinstance(payload, bytes):
            self._process_frame(payload)

    def _on_connection_lost(self, interface):
        if interface is self.mesh_interface and not self.detached:
            self.online = False
            RNS.log(f"Meshtastic connection lost for {self}", RNS.LOG_WARNING)

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
        if binascii.crc32(data).to_bytes(4, "big") != checksum:
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
        """Accept a binary frame from a Meshtastic callback or test."""
        self._process_frame(data)

    def process_outgoing(self, data):
        if self.detached or not self.online:
            return
        try:
            frames = MeshtasticFrameCodec.encode(data, self.payload_size)
            with self.send_lock:
                for frame in frames:
                    self.mesh_interface.sendData(
                        frame,
                        destinationId=self.destination,
                        portNum=self.port_num,
                        wantAck=self.want_ack,
                        channelIndex=self.channel,
                        hopLimit=self.hop_limit,
                    )
            self.txb += len(data)
        except Exception as error:
            RNS.log(f"Could not transmit on {self}: {error}", RNS.LOG_ERROR)

    def detach(self):
        self.detached = True
        self.online = False
        try:
            self.pub.unsubscribe(self._on_receive, "meshtastic.receive")
            self.pub.unsubscribe(self._on_connection_lost, "meshtastic.connection.lost")
            self.mesh_interface.close()
        except Exception as error:
            RNS.log(f"Could not close {self}: {error}", RNS.LOG_DEBUG)

    def __str__(self):
        return f"MeshtasticInterface[{self.name}]"


interface_class = MeshtasticInterface
