import queue
import threading
import unittest
from unittest.mock import Mock

from RNS.Interfaces.MeshtasticInterface import MeshtasticFrameCodec, MeshtasticInterface


class MeshtasticFrameCodecTest(unittest.TestCase):
    def test_reticulum_interface_defaults(self):
        self.assertEqual(MeshtasticInterface.DEFAULT_IFAC_SIZE, 8)
        self.assertEqual(MeshtasticInterface.DEFAULT_PAYLOAD_SIZE, 200)
        self.assertEqual(MeshtasticInterface.MAX_PAYLOAD_SIZE, 200)
        self.assertEqual(MeshtasticInterface.REQUIRED_HOP_LIMIT, 1)

    def test_payload_size_above_safe_limit_is_rejected(self):
        interface = self.make_interface()
        interface.payload_size = 201
        interface.max_pending_packets = 1
        interface.send_interval = 0
        interface.reconnect_interval = 1
        interface.max_reconnect_interval = 1

        with self.assertRaisesRegex(ValueError, "between 16 and 200"):
            interface._validate_config()

    def test_meshtastic_acknowledgements_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "want_ack = no"):
            MeshtasticInterface._validate_transport_policy(True, 1)

    def test_multihop_forwarding_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "hop_limit = 1"):
            MeshtasticInterface._validate_transport_policy(False, 2)

    def test_modem_preset_name_normalisation(self):
        normalise = MeshtasticInterface._normalise_modem_preset
        self.assertEqual(normalise("LongFast"), "LONG_FAST")
        self.assertEqual(normalise("very-long-slow"), "VERY_LONG_SLOW")
        self.assertEqual(normalise("NARROW_SLOW"), "NARROW_SLOW")

    def test_modem_preset_is_only_written_when_changed(self):
        interface = self.make_interface()
        interface.modem_preset_value = 2
        interface.ModemPreset = Mock()
        interface.ModemPreset.Name.return_value = "VERY_LONG_SLOW"
        connection = Mock()
        connection.localNode.localConfig.lora.modem_preset = 1

        interface._apply_modem_preset(connection)

        self.assertEqual(connection.localNode.localConfig.lora.modem_preset, 2)
        connection.localNode.writeConfig.assert_called_once_with("lora")

        connection.localNode.writeConfig.reset_mock()
        interface._apply_modem_preset(connection)
        connection.localNode.writeConfig.assert_not_called()

    def test_binary_round_trip_multiframe(self):
        packet = bytes(range(256)) + bytes(range(244))
        frames = MeshtasticFrameCodec.encode(packet, payload_size=80)
        self.assertGreater(len(frames), 1)

        decoded = [MeshtasticFrameCodec.decode(frame) for frame in reversed(frames)]
        self.assertTrue(all(decoded))
        transfer_id, _, count, checksum, _ = decoded[0]
        self.assertEqual(len(decoded), count)
        self.assertTrue(all(item[0] == transfer_id and item[3] == checksum for item in decoded))
        assembled = b"".join(item[4] for item in sorted(decoded, key=lambda item: item[1]))
        self.assertEqual(assembled, packet)
        self.assertEqual(len(frames[0]), 80)

    def test_rejects_invalid_frames(self):
        self.assertIsNone(MeshtasticFrameCodec.decode(b"ordinary Meshtastic packet"))
        self.assertIsNone(MeshtasticFrameCodec.decode(b"RNSM\x02" + bytes(20)))

    def test_receive_filters_meshtastic_channel(self):
        interface = MeshtasticInterface.__new__(MeshtasticInterface)
        mesh_interface = object()
        received = []
        interface.mesh_interface = mesh_interface
        interface.channel = 2
        interface.port_num = 76
        interface._process_frame = lambda payload, sender: received.append(payload)

        interface._on_receive(
            {"channel": 1, "decoded": {"portnum": 76, "payload": b"wrong"}},
            mesh_interface,
        )
        interface._on_receive(
            {"channel": 2, "decoded": {"portnum": 76, "payload": b"right"}},
            mesh_interface,
        )

        self.assertEqual(received, [b"right"])

    def test_receive_defaults_missing_channel_to_primary(self):
        interface = MeshtasticInterface.__new__(MeshtasticInterface)
        mesh_interface = object()
        received = []
        interface.mesh_interface = mesh_interface
        interface.channel = 0
        interface.port_num = 76
        interface._process_frame = lambda payload, sender: received.append(payload)

        interface._on_receive(
            {"decoded": {"portnum": "RETICULUM_TUNNEL_APP", "payload": b"primary"}},
            mesh_interface,
        )

        self.assertEqual(received, [b"primary"])

    def make_interface(self):
        interface = MeshtasticInterface.__new__(MeshtasticInterface)
        interface.name = "test"
        interface.fragments = {}
        interface.fragments_lock = threading.Lock()
        interface.payload_size = 233
        interface.reassembly_timeout = 30
        interface.max_reassemblies = 4
        interface.max_reassemblies_per_sender = 2
        interface.max_packet_size = 4096
        interface.owner = Mock()
        interface.rxb = 0
        return interface

    def test_reassembly_is_separated_by_sender(self):
        interface = self.make_interface()
        packet_a = b"A" * 300
        packet_b = b"B" * 300
        frames_a = MeshtasticFrameCodec.encode(packet_a, payload_size=80)
        frames_b = MeshtasticFrameCodec.encode(packet_b, payload_size=80)

        # Force the same transfer identifier to demonstrate that sender identity
        # remains part of the reassembly key.
        frames_b = [frame[:5] + frames_a[0][5:9] + frame[9:] for frame in frames_b]
        for frame_a, frame_b in zip(frames_a, frames_b):
            interface.process_incoming(frame_a, sender=1)
            interface.process_incoming(frame_b, sender=2)

        calls = [call.args[0] for call in interface.owner.inbound.call_args_list]
        self.assertEqual(calls, [packet_a, packet_b])

    def test_conflicting_fragment_discards_transfer(self):
        interface = self.make_interface()
        frames = MeshtasticFrameCodec.encode(b"test packet" * 20, payload_size=80)
        interface.process_incoming(frames[0], sender=1)
        conflicting = frames[0][:-1] + bytes([frames[0][-1] ^ 0xff])
        interface.process_incoming(conflicting, sender=1)

        self.assertEqual(interface.fragments, {})
        interface.owner.inbound.assert_not_called()

    def test_reassembly_limits_evict_oldest_sender_state(self):
        interface = self.make_interface()
        interface.max_reassemblies_per_sender = 1
        first = MeshtasticFrameCodec.encode(b"A" * 200, payload_size=80)
        second = MeshtasticFrameCodec.encode(b"B" * 200, payload_size=80)

        interface.process_incoming(first[0], sender=1)
        first_key = next(iter(interface.fragments))
        interface.process_incoming(second[0], sender=1)

        self.assertEqual(len(interface.fragments), 1)
        self.assertNotIn(first_key, interface.fragments)

    def test_oversized_transfer_is_discarded(self):
        interface = self.make_interface()
        interface.max_packet_size = 10
        frame = MeshtasticFrameCodec.encode(b"A" * 20, payload_size=80)[0]

        interface.process_incoming(frame, sender=1)

        self.assertEqual(interface.fragments, {})
        interface.owner.inbound.assert_not_called()

    def test_outgoing_fragments_are_paced(self):
        interface = self.make_interface()
        interface.detached = False
        interface.online = True
        interface.payload_size = 80
        interface.send_interval = 0.25
        interface.send_lock = threading.Lock()
        interface.mesh_interface = Mock()
        interface.destination = "^all"
        interface.port_num = 76
        interface.want_ack = False
        interface.channel = 0
        interface.hop_limit = None
        interface.txb = 0
        interface.reconnect_stop = Mock()
        interface.reconnect_stop.is_set.return_value = False
        interface.reconnect_stop.wait.return_value = False

        data = bytes(range(200))
        interface._transmit_packet(data)

        frame_count = len(MeshtasticFrameCodec.encode(data, 80))
        self.assertEqual(interface.mesh_interface.sendData.call_count, frame_count)
        for call in interface.mesh_interface.sendData.call_args_list:
            self.assertFalse(call.kwargs["wantAck"])
            self.assertEqual(call.kwargs["hopLimit"], 1)
        self.assertEqual(interface.reconnect_stop.wait.call_count, frame_count - 1)
        interface.reconnect_stop.wait.assert_called_with(0.25)

    def test_reconnect_replaces_lost_interface(self):
        interface = self.make_interface()
        previous = Mock()
        replacement = Mock()
        replacement.isConnected.is_set.return_value = True
        interface.mesh_interface = previous
        interface.connection_lock = threading.Lock()
        interface.detached = False
        interface.online = False
        interface.reconnect_interval = 1
        interface.max_reconnect_interval = 4
        interface.reconnect_stop = Mock()
        interface.reconnect_stop.wait.return_value = False
        interface._connect = Mock(return_value=replacement)

        interface._reconnect_loop()

        self.assertIs(interface.mesh_interface, replacement)
        self.assertTrue(interface.online)
        previous.close.assert_called_once_with()

    def test_ble_disconnect_callback_only_publishes_loss(self):
        connection = Mock()
        bleak_client = Mock()
        backend = Mock()
        bleak_client._backend = backend
        connection.client.bleak_client = bleak_client

        MeshtasticInterface._configure_ble_disconnect(connection)
        callback = backend.set_disconnected_callback.call_args.args[0]
        callback()

        connection._disconnected.assert_called_once_with()
        connection.close.assert_not_called()

    def test_full_outbound_queue_drops_without_blocking(self):
        interface = self.make_interface()
        interface.detached = False
        interface.online = True
        interface.outbound_queue = queue.Queue(maxsize=1)
        interface.outbound_queue.put_nowait(b"already queued")

        interface.process_outgoing(b"new packet")

        self.assertEqual(interface.outbound_queue.qsize(), 1)
        self.assertEqual(interface.outbound_queue.get_nowait(), b"already queued")


if __name__ == "__main__":
    unittest.main()
