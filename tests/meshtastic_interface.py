import binascii
import unittest

from RNS.Interfaces.MeshtasticInterface import MeshtasticFrameCodec


class MeshtasticFrameCodecTest(unittest.TestCase):
    def test_round_trip_multiframe(self):
        packet = bytes(range(256)) + bytes(range(244))
        frames = MeshtasticFrameCodec.encode(packet, text_limit=80)
        self.assertGreater(len(frames), 1)

        decoded = [MeshtasticFrameCodec.decode(frame) for frame in reversed(frames)]
        self.assertTrue(all(decoded))
        transfer_id, _, count, checksum, _ = decoded[0]
        self.assertEqual(len(decoded), count)
        self.assertTrue(all(item[0] == transfer_id and item[3] == checksum for item in decoded))
        assembled = b"".join(item[4] for item in sorted(decoded, key=lambda item: item[1]))
        self.assertEqual(assembled, packet)
        self.assertEqual(checksum, f"{binascii.crc32(assembled) & 0xffffffff:08x}")

    def test_rejects_invalid_frames(self):
        self.assertIsNone(MeshtasticFrameCodec.decode("ordinary Meshtastic chat"))
        self.assertIsNone(MeshtasticFrameCodec.decode("RNSMT1:deadbeef:01:01:00000000:not*base64"))


if __name__ == "__main__":
    unittest.main()
