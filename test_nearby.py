import os
import struct
import sys
import unittest

import nearby as nb


def report(addr, data, rssi, event_type=0x03):
    raw = bytes.fromhex(addr.replace(":", ""))[::-1]
    return bytes([event_type, 0x01]) + raw + bytes([len(data)]) + data + struct.pack("b", rssi)


def le_meta(*reports):
    body = bytes([nb.LE_ADV_REPORT, len(reports)]) + b"".join(reports)
    return bytes([nb.HCI_EVENT_PKT, nb.EVT_LE_META, len(body)]) + body


BEACON = nb.adv_data()[1:]


class Packets(unittest.TestCase):
    def test_command_bytes(self):
        self.assertEqual(nb.command(nb.LE_SET_SCAN_ENABLE, b"\1\0"), bytes.fromhex("010c20020100"))

    def test_filter_is_kernel_sized(self):
        f = nb.hci_filter()
        self.assertEqual(len(f), 16)
        types, ev0, ev1, _ = struct.unpack("<IIIH2x", f)
        self.assertEqual(types, 1 << 4)
        self.assertEqual(ev0, (1 << 0x0E) | (1 << 0x0F))
        self.assertEqual(ev1, 1 << (0x3E - 32))

    def test_adv_data_fits_and_is_ours(self):
        d = nb.adv_data()
        self.assertEqual(len(d), 32)
        self.assertEqual(d[0], 19)
        self.assertTrue(nb.is_beacon(d[1:]))

    def test_other_devices_are_not_beacons(self):
        other = bytes([17, 0x21]) + bytes(16)
        self.assertFalse(nb.is_beacon(other))
        self.assertFalse(nb.is_beacon(b""))
        self.assertFalse(nb.is_beacon(BEACON[:10]))  # cut short
        self.assertFalse(nb.is_beacon(bytes([2, 0x01, 0x06])))  # flags only

    def test_parse_two_reports(self):
        pkt = le_meta(report("AA:BB:CC:DD:EE:01", BEACON[:19], -48),
                      report("11:22:33:44:55:66", b"\x02\x01\x06", -90))
        got = list(nb.adv_reports(pkt))
        self.assertEqual(got, [("AA:BB:CC:DD:EE:01", BEACON[:19], -48),
                               ("11:22:33:44:55:66", b"\x02\x01\x06", -90)])

    def test_truncated_or_foreign_events_ignored(self):
        pkt = le_meta(report("AA:BB:CC:DD:EE:01", BEACON[:19], -48))
        self.assertEqual(list(nb.adv_reports(pkt[:-1])), [])  # RSSI missing
        self.assertEqual(list(nb.adv_reports(b"\x04\x3e")), [])
        self.assertEqual(list(nb.adv_reports(b"\x04\x0e\x04\x01\x0c\x20\x00")), [])

    def test_command_replies(self):
        self.assertEqual(nb.command_reply(bytes.fromhex("040e04010c2000")), (nb.LE_SET_SCAN_ENABLE, 0))
        self.assertEqual(nb.command_reply(bytes.fromhex("040f040c010c20")), (nb.LE_SET_SCAN_ENABLE, 0x0C))
        self.assertIsNone(nb.command_reply(le_meta()))

    def test_private_address(self):
        for _ in range(200):
            a = nb.new_private_address()
            self.assertEqual(a[5] >> 6, 0)  # non-resolvable private
        picks = iter([bytes(6), b"\xff" * 6, b"\x01\x02\x03\x04\x05\x06"])
        self.assertEqual(nb.new_private_address(lambda n: next(picks)), b"\x01\x02\x03\x04\x05\x06")


class FakeSock:
    def __init__(self, replies):
        self.sent, self.replies = [], list(replies)

    def send(self, b):
        self.sent.append(b)

    def settimeout(self, t):
        pass

    def recv(self, n):
        if not self.replies:
            raise nb.socket.timeout
        return self.replies.pop(0)


class RadioSend(unittest.TestCase):
    def radio(self, replies):
        r = nb.Radio.__new__(nb.Radio)
        r.sock = FakeSock(replies)
        return r

    def test_skips_adverts_until_reply(self):
        r = self.radio([le_meta(report("AA:BB:CC:DD:EE:01", BEACON[:19], -48)),
                        bytes.fromhex("040e04010c2000")])
        self.assertEqual(r.send(nb.LE_SET_SCAN_ENABLE, b"\1\0"), 0)

    def test_failure_raises_unless_unchecked(self):
        disallowed = bytes.fromhex("040e04010c200c")
        with self.assertRaises(nb.HciError):
            self.radio([disallowed]).send(nb.LE_SET_SCAN_ENABLE, b"\1\0")
        self.assertEqual(self.radio([disallowed]).send(nb.LE_SET_SCAN_ENABLE, b"\1\0", check=False), 0x0C)

    def test_no_reply_raises(self):
        with self.assertRaises(nb.HciError):
            self.radio([]).send(nb.LE_SET_SCAN_ENABLE, b"\1\0")


class Tracking(unittest.TestCase):
    def feed(self, t, addr, start, end, rssi=-60):
        x = start
        while x <= end:
            t.seen(addr, rssi, x)
            x += 0.5

    def test_new_person_beeps_once_after_settling(self):
        t = nb.Tracker()
        t.seen("A", -50, 0)
        self.assertEqual(t.tick(1), 0)
        self.feed(t, "A", 0, 6, rssi=-50)
        self.assertEqual(t.tick(6), 1)
        self.assertEqual(t.tick(6.5), 0)
        self.assertEqual(t.present(6.5), [("right here", -50)])

    def test_two_people_two_beeps(self):
        t = nb.Tracker()
        self.feed(t, "A", 0, 6)
        self.feed(t, "B", 0, 6, rssi=-80)
        self.assertEqual(t.tick(6), 2)
        self.assertEqual([lbl for lbl, _ in t.present(6)], ["close", "nearby"])

    def test_address_rotation_is_not_a_new_person(self):
        for gap in (0.2, 2, 6):  # gaps measured on real hardware: 1.9 s to 6 s
            t = nb.Tracker()
            self.feed(t, "OLD", 0, 10)
            self.assertEqual(t.tick(10), 1)
            end = 10 + gap + 6
            self.feed(t, "NEW", 10 + gap, end)
            self.assertEqual(t.tick(end), 0, gap)
            self.assertEqual(len(t.present(end)), 1)
            self.assertNotIn("OLD", t.peers)

    def test_first_person_silent_for_a_while_still_counts_second(self):
        t = nb.Tracker()
        self.feed(t, "A", 0, 10)
        t.tick(10)
        self.feed(t, "B", 11, 17)
        self.feed(t, "A", 14, 17)  # A was quiet 4 s, then heard again
        self.assertEqual(t.tick(17), 1)
        self.assertEqual(len(t.present(17)), 2)

    def test_second_person_while_first_stays_still_beeps(self):
        t = nb.Tracker()
        self.feed(t, "A", 0, 10)
        t.tick(10)
        self.feed(t, "A", 10, 20)
        self.feed(t, "B", 12, 20)
        self.assertEqual(t.tick(20), 1)
        self.assertEqual(len(t.present(20)), 2)

    def test_gone_after_timeout_and_back_beeps_again(self):
        t = nb.Tracker()
        self.feed(t, "A", 0, 6)
        t.tick(6)
        self.assertEqual(t.tick(6 + nb.LOST_AFTER + 1), 0)
        self.assertEqual(t.present(20), [])
        t.tick(25)  # the real loop ticks every half second; A is forgotten by now
        self.feed(t, "A", 30, 36)
        self.assertEqual(t.tick(36), 1)


class Screen(unittest.TestCase):
    def test_fits_console(self):
        people = [("close", -60)] * 9
        for text in (nb.screen([]), nb.screen(people)):
            lines = text.split("\n")
            self.assertLessEqual(len(lines), 10)
            self.assertTrue(all(len(line) <= 40 for line in lines), lines)
        self.assertIn("and 2 more", nb.screen(people))

    @unittest.skipUnless(sys.platform.startswith("linux"), "select on pipes needs Linux")
    def test_quit_keys(self):
        for typed, want in ((b"", False), (b"q", True), (b"Q", True), (b"\x1b", True),
                            (b"\x1b[A", False), (b"x", False)):
            r, w = os.pipe()
            try:
                if typed:
                    os.write(w, typed)
                self.assertEqual(nb.quit_pressed(r), want, typed)
            finally:
                os.close(r)
                os.close(w)

    def test_beep_plays_as_sudo_user(self):
        env = {"SUDO_USER": "alice", "SUDO_UID": "1000"}
        self.assertEqual(nb.beep_command("/tmp/b.wav", env, 0),
                         ["runuser", "-u", "alice", "--", "env", "XDG_RUNTIME_DIR=/run/user/1000",
                          "aplay", "-q", "/tmp/b.wav"])
        self.assertEqual(nb.beep_command("/tmp/b.wav", {}, 0), ["aplay", "-q", "/tmp/b.wav"])
        self.assertEqual(nb.beep_command("/tmp/b.wav", env, 1000), ["aplay", "-q", "/tmp/b.wav"])
        self.assertEqual(nb.beep_command("/tmp/b.wav", {"SUDO_USER": "x", "SUDO_UID": "1;rm"}, 0),
                         ["aplay", "-q", "/tmp/b.wav"])

    def test_beep_file_is_valid_wav(self):
        import os
        import tempfile
        import wave
        fd, path = tempfile.mkstemp(suffix=".wav")
        os.close(fd)
        try:
            nb.make_beep(path)
            with wave.open(path) as w:
                self.assertEqual(w.getframerate(), 16000)
                self.assertGreater(w.getnframes(), 3000)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
