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


if __name__ == "__main__":
    unittest.main()
