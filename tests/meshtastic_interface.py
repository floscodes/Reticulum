import unittest

from RNS.Interfaces.MeshtasticInterface import MeshtasticFrameCodec, MeshtasticInterface


class MeshtasticFrameCodecTest(unittest.TestCase):
    def test_reticulum_interface_defaults(self):
        self.assertEqual(MeshtasticInterface.DEFAULT_IFAC_SIZE, 8)

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
        interface._process_frame = received.append

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
        interface._process_frame = received.append

        interface._on_receive(
            {"decoded": {"portnum": "RETICULUM_TUNNEL_APP", "payload": b"primary"}},
            mesh_interface,
        )

        self.assertEqual(received, [b"primary"])


if __name__ == "__main__":
    unittest.main()
