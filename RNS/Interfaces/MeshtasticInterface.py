# Reticulum License
#
# Copyright (c) 2026 floscodes
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
# - The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Reticulum transport over Meshtastic port 76, reserved for Reticulum."""

import binascii
import os
import queue
import re
import threading
import time

import RNS
from RNS.Interfaces.Interface import Interface


class MeshtasticFrameCodec:
    """Fragment RNS packets into Meshtastic binary payloads.

    This interface deliberately caps application payloads at 200 bytes, below
    Meshtastic's theoretical limit. The header keeps fragment reassembly
    internal to this interface and never turns binary RNS traffic into text.
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
    # Although Meshtastic defines a 233-byte application maximum, some real
    # BLE/firmware combinations drop frames at that exact boundary. Keeping
    # headroom here is more reliable and matches established tunnel practice.
    DEFAULT_PAYLOAD_SIZE = 200
    MAX_PAYLOAD_SIZE = 200
    DEFAULT_REASSEMBLY_TIMEOUT = 300
    DEFAULT_SEND_INTERVAL = 1.0
    DEFAULT_RECONNECT_INTERVAL = 5.0
    DEFAULT_MAX_RECONNECT_INTERVAL = 60.0
    DEFAULT_MAX_REASSEMBLIES = 64
    DEFAULT_MAX_REASSEMBLIES_PER_SENDER = 8
    DEFAULT_MAX_PACKET_SIZE = 65535
    DEFAULT_MAX_PENDING_PACKETS = 128
    DEFAULT_HOP_LIMIT = 1
    ALLOWED_HOP_LIMITS = (0, 1)

    def __init__(self, owner, configuration):
        super().__init__()
        c = Interface.get_config_obj(configuration)
        self.owner = owner
        self.name = c["name"]
        self.channel = c.as_int("channel") if "channel" in c else 0
        self.modem_preset = c["modem_preset"] if "modem_preset" in c and c["modem_preset"] else None
        self.destination = c["destination"] if "destination" in c else "^all"
        self.payload_size = c.as_int("payload_size") if "payload_size" in c else self.DEFAULT_PAYLOAD_SIZE
        self.reassembly_timeout = c.as_float("reassembly_timeout") if "reassembly_timeout" in c else self.DEFAULT_REASSEMBLY_TIMEOUT
        self.max_reassemblies = c.as_int("max_reassemblies") if "max_reassemblies" in c else self.DEFAULT_MAX_REASSEMBLIES
        self.max_reassemblies_per_sender = c.as_int("max_reassemblies_per_sender") if "max_reassemblies_per_sender" in c else self.DEFAULT_MAX_REASSEMBLIES_PER_SENDER
        self.max_packet_size = c.as_int("max_packet_size") if "max_packet_size" in c else self.DEFAULT_MAX_PACKET_SIZE
        self.max_pending_packets = c.as_int("max_pending_packets") if "max_pending_packets" in c else self.DEFAULT_MAX_PENDING_PACKETS
        self.connection_timeout = c.as_int("connection_timeout") if "connection_timeout" in c else 30
        self.send_interval = c.as_float("send_interval") if "send_interval" in c else self.DEFAULT_SEND_INTERVAL
        self.reconnect_interval = c.as_float("reconnect_interval") if "reconnect_interval" in c else self.DEFAULT_RECONNECT_INTERVAL
        self.max_reconnect_interval = c.as_float("max_reconnect_interval") if "max_reconnect_interval" in c else self.DEFAULT_MAX_RECONNECT_INTERVAL
        configured_want_ack = c.as_bool("want_ack") if "want_ack" in c else False
        configured_hop_limit = c.as_int("hop_limit") if "hop_limit" in c else self.DEFAULT_HOP_LIMIT
        self._validate_transport_policy(configured_want_ack, configured_hop_limit)
        # Reticulum supplies its own reliability mechanisms. Meshtastic ACKs
        # would add redundant traffic, while zero or one permitted relay bounds
        # fragment flooding on the shared LoRa channel.
        self.want_ack = False
        self.hop_limit = configured_hop_limit
        self.bitrate = c.as_int("bitrate") if "bitrate" in c else self.DEFAULT_BITRATE
        self._validate_config()
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
        self.connection_lock = threading.Lock()
        self.reconnect_stop = threading.Event()
        self.reconnect_thread = None
        self.outbound_queue = queue.Queue(maxsize=self.max_pending_packets)

        self.port, self.host, self.ble = self._connection_config(c)
        self._load_meshtastic()
        self.modem_preset_value = self._resolve_modem_preset(self.modem_preset)
        self.mesh_interface = self._connect()
        self.pub.subscribe(self._on_receive, "meshtastic.receive")
        self.pub.subscribe(self._on_connection_lost, "meshtastic.connection.lost")
        self.pub.subscribe(self._on_connection_established, "meshtastic.connection.established")
        self.online = self.mesh_interface.isConnected.is_set()
        self.sender_thread = threading.Thread(
            target=self._sender_loop,
            name=f"meshtastic-sender-{self.name}",
            daemon=True,
        )
        self.sender_thread.start()
        RNS.log(f"Meshtastic binary interface {self} is ready", RNS.LOG_NOTICE)

    @classmethod
    def _validate_transport_policy(cls, want_ack, hop_limit):
        """Enforce Reticulum-safe Meshtastic forwarding invariants."""
        if want_ack:
            raise ValueError("MeshtasticInterface requires want_ack = no")
        if hop_limit not in cls.ALLOWED_HOP_LIMITS:
            raise ValueError(
                "MeshtasticInterface requires hop_limit to be 0 or 1"
            )

    def _validate_config(self):
        """Reject unsafe limits early instead of failing in callback threads."""
        if not MeshtasticFrameCodec.HEADER_SIZE < self.payload_size <= self.MAX_PAYLOAD_SIZE:
            raise ValueError(
                f"payload_size must be between {MeshtasticFrameCodec.HEADER_SIZE + 1} "
                f"and {self.MAX_PAYLOAD_SIZE}"
            )
        if self.reassembly_timeout <= 0:
            raise ValueError("reassembly_timeout must be greater than zero")
        if self.max_reassemblies < 1 or self.max_reassemblies_per_sender < 1:
            raise ValueError("Meshtastic reassembly limits must be greater than zero")
        if self.max_reassemblies_per_sender > self.max_reassemblies:
            raise ValueError("max_reassemblies_per_sender cannot exceed max_reassemblies")
        if self.max_packet_size < 1:
            raise ValueError("max_packet_size must be greater than zero")
        if self.max_pending_packets < 1:
            raise ValueError("max_pending_packets must be greater than zero")
        if self.send_interval < 0:
            raise ValueError("send_interval cannot be negative")
        if self.reconnect_interval <= 0 or self.max_reconnect_interval < self.reconnect_interval:
            raise ValueError(
                "Reconnect intervals must be positive and max_reconnect_interval "
                "cannot be smaller than reconnect_interval"
            )
        if not 0 <= self.channel <= 7:
            raise ValueError("Meshtastic channel must be between 0 and 7")

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
            from meshtastic.protobuf import config_pb2
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
        self.ModemPreset = config_pb2.Config.LoRaConfig.ModemPreset
        self.port_num = portnums_pb2.PortNum.RETICULUM_TUNNEL_APP
        self.SerialInterface = SerialInterface
        self.TCPInterface = TCPInterface
        self.BLEInterface = BLEInterface

    def _connect(self):
        options = {"noNodes": True, "timeout": self.connection_timeout}
        if self.port:
            connection = self.SerialInterface(devPath=self.port, **options)
        elif self.host:
            connection = self.TCPInterface(hostname=self.host, **options)
        elif self.ble:
            connection = self.BLEInterface(address=self.ble, **options)
            self._configure_ble_disconnect(connection)
        else:
            connection = self.SerialInterface(**options)
        self._apply_modem_preset(connection)
        return connection

    @staticmethod
    def _normalise_modem_preset(value):
        """Convert LongFast, long-fast and LONG_FAST to protobuf spelling."""
        value = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(value).strip())
        return value.replace("-", "_").replace(" ", "_").upper()

    def _resolve_modem_preset(self, value):
        if value is None:
            return None
        name = self._normalise_modem_preset(value)
        try:
            return self.ModemPreset.Value(name)
        except ValueError as error:
            available = ", ".join(self.ModemPreset.keys())
            raise ValueError(
                f"Unknown Meshtastic modem_preset {value!r}; available presets: {available}"
            ) from error

    def _apply_modem_preset(self, connection):
        """Persist the requested preset without rewriting unchanged radios."""
        if self.modem_preset_value is None:
            return
        node = getattr(connection, "localNode", None)
        if node is None or getattr(node, "localConfig", None) is None:
            raise RuntimeError("Meshtastic radio configuration is not available")
        lora_config = node.localConfig.lora
        if lora_config.modem_preset == self.modem_preset_value:
            return
        lora_config.modem_preset = self.modem_preset_value
        node.writeConfig("lora")
        RNS.log(
            f"Applied Meshtastic modem preset "
            f"{self.ModemPreset.Name(self.modem_preset_value)} on {self}",
            RNS.LOG_NOTICE,
        )

    @staticmethod
    def _configure_ble_disconnect(connection):
        """Keep Meshtastic's BLE callback from closing its own event thread.

        On Windows, the library callback calls ``close()`` from Bleak's
        disconnected callback. That cleanup can recursively disconnect and
        join the event thread that is currently executing it. Publishing the
        normal Meshtastic disconnect event is sufficient here: our reconnect
        worker later closes the stale wrapper from a safe thread.
        """
        client = getattr(getattr(connection, "client", None), "bleak_client", None)
        if client is None:
            return

        # Current Bleak exposes callback replacement on the selected backend,
        # not on its public facade. Backend callbacks receive no arguments.
        backend = getattr(client, "_backend", client)
        callback = lambda: connection._disconnected()
        setter = getattr(backend, "set_disconnected_callback", None)
        if callable(setter):
            setter(callback)
        else:
            # Bleak versions without the public setter store the callback here.
            backend._disconnected_callback = callback

    def _on_receive(self, packet, interface):
        if interface is not self.mesh_interface:
            return
        if packet.get("channel", 0) != self.channel:
            return
        decoded = packet.get("decoded", {})
        port_num = decoded.get("portnum")
        if port_num not in (self.port_num, "RETICULUM_TUNNEL_APP"):
            return
        payload = decoded.get("payload")
        if isinstance(payload, bytes):
            # A transfer identifier is intentionally scoped to its Meshtastic
            # sender. This prevents fragments from different radios with a
            # coincidentally identical random transfer ID from being combined.
            # Synthetic/test packets may omit it and share an explicit fallback
            # namespace; real Meshtastic receive packets include one of these.
            sender = packet.get("fromId") or packet.get("from") or "unknown"
            self._process_frame(payload, sender)

    def _on_connection_lost(self, interface):
        if interface is self.mesh_interface and not self.detached:
            self.online = False
            RNS.log(f"Meshtastic connection lost for {self}", RNS.LOG_WARNING)
            self._start_reconnect()

    def _on_connection_established(self, interface):
        if interface is self.mesh_interface and not self.detached:
            self.online = True
            RNS.log(f"Meshtastic connection established for {self}", RNS.LOG_NOTICE)

    def _start_reconnect(self):
        """Start at most one reconnect worker for a lost radio connection."""
        with self.connection_lock:
            if self.detached or (
                self.reconnect_thread is not None and self.reconnect_thread.is_alive()
            ):
                return
            self.reconnect_thread = threading.Thread(
                target=self._reconnect_loop,
                name=f"meshtastic-reconnect-{self.name}",
                daemon=True,
            )
            self.reconnect_thread.start()

    def _reconnect_loop(self):
        """Reconnect with bounded exponential backoff until detached."""
        delay = self.reconnect_interval
        while not self.reconnect_stop.wait(delay):
            if self.detached:
                return
            RNS.log(f"Attempting to reconnect {self}", RNS.LOG_VERBOSE)
            try:
                replacement = self._connect()
                with self.connection_lock:
                    if self.detached:
                        replacement.close()
                        return
                    previous = self.mesh_interface
                    self.mesh_interface = replacement
                    self.online = replacement.isConnected.is_set()
                if previous is not replacement:
                    try:
                        previous.close()
                    except Exception:
                        pass
                if self.online:
                    RNS.log(f"Reconnected {self}", RNS.LOG_NOTICE)
                    return
            except Exception as error:
                RNS.log(f"Could not reconnect {self}: {error}", RNS.LOG_WARNING)
            delay = min(delay * 2, self.max_reconnect_interval)

    def _process_frame(self, frame, sender):
        if len(frame) > self.payload_size:
            RNS.log(f"Discarding oversized Meshtastic frame on {self}", RNS.LOG_WARNING)
            return
        decoded = MeshtasticFrameCodec.decode(frame)
        if decoded is None:
            return
        transfer_id, index, count, checksum, payload = decoded
        key = (sender, transfer_id)
        now = time.monotonic()
        with self.fragments_lock:
            self._expire_fragments(now)
            entry = self.fragments.get(key)
            if entry is None:
                self._make_reassembly_room(sender)
                entry = {
                    "created": now,
                    "updated": now,
                    "count": count,
                    "checksum": checksum,
                    "size": 0,
                    "parts": {},
                }
                self.fragments[key] = entry
            elif entry["count"] != count or entry["checksum"] != checksum:
                # Reusing a transfer ID with conflicting metadata is malformed.
                # Discard both interpretations instead of assembling ambiguity.
                self.fragments.pop(key, None)
                RNS.log(f"Discarding inconsistent Meshtastic transfer on {self}", RNS.LOG_WARNING)
                return

            previous = entry["parts"].get(index)
            if previous is not None and previous != payload:
                self.fragments.pop(key, None)
                RNS.log(f"Discarding conflicting Meshtastic fragment on {self}", RNS.LOG_WARNING)
                return
            if previous is None:
                entry["parts"][index] = payload
                entry["size"] += len(payload)
            entry["updated"] = now
            if entry["size"] > self.max_packet_size:
                self.fragments.pop(key, None)
                RNS.log(f"Discarding oversized Meshtastic transfer on {self}", RNS.LOG_WARNING)
                return
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
        # Activity-based expiry permits a slow but progressing transfer while
        # ensuring abandoned state cannot remain in memory indefinitely.
        expired = [
            key for key, value in self.fragments.items()
            if now - value["updated"] > self.reassembly_timeout
        ]
        for key in expired:
            self.fragments.pop(key, None)

    def _make_reassembly_room(self, sender):
        """Enforce global and per-sender limits using oldest-entry eviction."""
        sender_keys = [key for key in self.fragments if key[0] == sender]
        while len(sender_keys) >= self.max_reassemblies_per_sender:
            oldest = min(sender_keys, key=lambda key: self.fragments[key]["updated"])
            self.fragments.pop(oldest, None)
            sender_keys.remove(oldest)
        while len(self.fragments) >= self.max_reassemblies:
            oldest = min(self.fragments, key=lambda key: self.fragments[key]["updated"])
            self.fragments.pop(oldest, None)

    def process_incoming(self, data, sender="local"):
        """Accept a binary frame from a Meshtastic callback or test."""
        self._process_frame(data, sender)

    def process_outgoing(self, data):
        if self.detached or not self.online:
            return
        try:
            # Keep the Reticulum transport thread non-blocking while the
            # dedicated sender applies radio-friendly pacing.
            self.outbound_queue.put_nowait(bytes(data))
        except queue.Full:
            RNS.log(f"Outbound Meshtastic queue is full on {self}", RNS.LOG_WARNING)

    def _sender_loop(self):
        while not self.reconnect_stop.is_set():
            try:
                data = self.outbound_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._transmit_packet(data)
            finally:
                self.outbound_queue.task_done()

    def _transmit_packet(self, data):
        """Send one queued RNS packet without blocking Reticulum itself."""
        try:
            frames = MeshtasticFrameCodec.encode(data, self.payload_size)
            with self.send_lock:
                for index, frame in enumerate(frames):
                    if self.detached or not self.online:
                        return
                    self.mesh_interface.sendData(
                        frame,
                        destinationId=self.destination,
                        portNum=self.port_num,
                        # This invariant is intentionally explicit at the API
                        # boundary so later configuration changes cannot enable
                        # redundant Meshtastic acknowledgements.
                        wantAck=False,
                        channelIndex=self.channel,
                        hopLimit=self.hop_limit,
                    )
                    # The delay is between fragments, never after the last one.
                    if self.send_interval and index + 1 < len(frames):
                        if self.reconnect_stop.wait(self.send_interval):
                            return
            self.txb += len(data)
        except Exception as error:
            self.online = False
            RNS.log(f"Could not transmit on {self}: {error}", RNS.LOG_ERROR)
            self._start_reconnect()

    def detach(self):
        self.detached = True
        self.online = False
        self.reconnect_stop.set()
        try:
            self.pub.unsubscribe(self._on_receive, "meshtastic.receive")
            self.pub.unsubscribe(self._on_connection_lost, "meshtastic.connection.lost")
            self.pub.unsubscribe(self._on_connection_established, "meshtastic.connection.established")
            self.mesh_interface.close()
        except Exception as error:
            RNS.log(f"Could not close {self}: {error}", RNS.LOG_DEBUG)

    def __str__(self):
        return f"MeshtasticInterface[{self.name}]"


interface_class = MeshtasticInterface
