import json
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
import wave

import nearbyd as nb


def report(addr, data, rssi, event_type=0x03):
    raw = bytes.fromhex(addr.replace(":", ""))[::-1]
    return bytes([event_type, 0x01]) + raw + bytes([len(data)]) + data + struct.pack("b", rssi)


def le_meta(*reports):
    body = bytes([nb.LE_ADV_REPORT, len(reports)]) + b"".join(reports)
    return bytes([nb.HCI_EVENT_PKT, nb.EVT_LE_META, len(body)]) + body


def profile(cid, nick="anon", colour=1, status="", avatar="00" * 32, rev=0):
    return {"id": cid, "nick": nick, "colour": colour, "status": status, "avatar": avatar,
            "rev": rev, "listen_only": False, "muted": []}


def deliver(sender, receiver, now=0.0, wall=1000.0, rssi=-50):
    """Put every packet in sender's current cycle on air to receiver; return beeps."""
    return [receiver.on_advert(p, rssi, now, wall) for p in sender.schedule(now)]


class Hci(unittest.TestCase):
    def test_command_bytes(self):
        self.assertEqual(nb.command(nb.LE_SET_SCAN_ENABLE, b"\1\0"), bytes.fromhex("010c20020100"))

    def test_filter_is_kernel_sized(self):
        f = nb.hci_filter()
        self.assertEqual(len(f), 16)
        types, ev0, ev1, _ = struct.unpack("<IIIH2x", f)
        self.assertEqual(types, 1 << 4)
        self.assertEqual(ev0, (1 << 0x0E) | (1 << 0x0F))
        self.assertEqual(ev1, 1 << (0x3E - 32))

    def test_parse_two_reports(self):
        pkt = le_meta(report("AA:BB:CC:DD:EE:01", b"\x02\x01\x06", -48),
                      report("11:22:33:44:55:66", b"\x02\x01\x05", -90))
        self.assertEqual(list(nb.adv_reports(pkt)), [("AA:BB:CC:DD:EE:01", b"\x02\x01\x06", -48),
                                                     ("11:22:33:44:55:66", b"\x02\x01\x05", -90)])

    def test_truncated_or_foreign_events_ignored(self):
        pkt = le_meta(report("AA:BB:CC:DD:EE:01", b"\x02\x01\x06", -48))
        self.assertEqual(list(nb.adv_reports(pkt[:-1])), [])
        self.assertEqual(list(nb.adv_reports(b"\x04\x3e")), [])
        self.assertEqual(list(nb.adv_reports(b"\x04\x0e\x04\x01\x0c\x20\x00")), [])

    def test_command_replies(self):
        self.assertEqual(nb.command_reply(bytes.fromhex("040e04010c2000")), (nb.LE_SET_SCAN_ENABLE, 0))
        self.assertEqual(nb.command_reply(bytes.fromhex("040f040c010c20")), (nb.LE_SET_SCAN_ENABLE, 0x0C))
        self.assertIsNone(nb.command_reply(le_meta()))

    def test_private_address(self):
        for _ in range(200):
            self.assertEqual(nb.new_private_address()[5] >> 6, 0)
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
        r = self.radio([le_meta(report("AA:BB:CC:DD:EE:01", b"\x02\x01\x06", -48)),
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


class Packets(unittest.TestCase):
    def test_longest_fields_fit_in_31_bytes(self):
        me = profile("abcdef", nick="x" * 10, status="y" * 20, avatar="ff" * 32)
        node = nb.Node(me)
        node.met["123456"] = {"nick": "z"}
        node.command({"cmd": "wave", "to": "123456", "text": "w" * 40}, 0)
        for p in node.schedule(0):
            self.assertLessEqual(len(p), 31)
            self.assertEqual(len(nb.adv_params(p)), 32)

    def test_round_trip(self):
        p = nb.packet(nb.STATUS, bytes.fromhex("a1b2c3"), b"\x07hello")
        self.assertEqual(nb.parse(p), (nb.STATUS, "a1b2c3", b"\x07hello"))

    def test_foreign_adverts_ignored(self):
        self.assertIsNone(nb.parse(b""))
        self.assertIsNone(nb.parse(bytes([2, 0x01, 0x06])))                        # flags only
        self.assertIsNone(nb.parse(bytes([8, 0xFF, 0x4C, 0x00, 1, 2, 3, 4, 5])))   # someone else's company id
        self.assertIsNone(nb.parse(bytes([9, 0xFF, 0xFF, 0xFF, 0xB6, 0x11, 1, 2, 3])))  # wrong magic
        self.assertIsNone(nb.parse(bytes([9, 0xFF, 0xFF, 0xFF, 0xB7, 0x21, 1, 2, 3])))  # future version
        self.assertIsNone(nb.parse(bytes([5, 0xFF, 0xFF, 0xFF, 0xB7, 0x11])))      # too short

    def test_schedule_sends_card_most_and_interleaves_waves(self):
        seq = nb.schedule(["C", "S", "A0", "A1"])
        self.assertEqual(seq, ["C", "S", "C", "A0", "C", "A1"])
        self.assertEqual(nb.schedule(["C", "S", "A0", "A1"], "W")[:4], ["C", "W", "S", "W"])

    def test_clean_strips_control_and_escape_codes(self):
        self.assertEqual(nb.clean(b"hi\x1b[2J\x07there\xff", 20), "hi[2Jthere")
        self.assertEqual(nb.clean("a" * 30, 10), "a" * 10)


class Swap(unittest.TestCase):
    def setUp(self):
        self.a = nb.Node(profile("aaaaaa", nick="Ada", colour=2, status="hello", avatar="0f" * 32))
        self.b = nb.Node(profile("bbbbbb", nick="Bo"))

    def test_full_card_arrives(self):
        deliver(self.a, self.b, wall=500.0)
        rec = self.b.met["aaaaaa"]
        self.assertEqual((rec["nick"], rec["colour"], rec["status"], rec["avatar"]),
                         ("Ada", 2, "hello", "0f" * 32))
        self.assertEqual((rec["first"], rec["last"], rec["count"]), (500.0, 500.0, 1))
        self.assertEqual([p["nick"] for p in self.b.around(0)], ["Ada"])

    def test_status_before_card_is_ignored(self):
        status = nb.card_packets(self.a.me)[1]
        self.b.on_advert(status, -50, 0, 0)
        self.assertNotIn("aaaaaa", self.b.met)

    def test_edit_bumps_rev_and_old_parts_are_ignored(self):
        old_status = nb.card_packets(self.a.me)[1]
        deliver(self.a, self.b)
        self.a.command({"cmd": "set_card", "status": "new"}, 0)
        self.b.on_advert(nb.card_packets(self.a.me)[0], -50, 1, 1001)  # new card (new rev)
        self.b.on_advert(old_status, -50, 1, 1001)                       # stale status: ignored
        self.assertEqual(self.b.met["aaaaaa"]["status"], "hello")
        self.b.on_advert(nb.card_packets(self.a.me)[1], -50, 1, 1001)
        self.assertEqual(self.b.met["aaaaaa"]["status"], "new")

    def test_meeting_counts(self):
        deliver(self.a, self.b, wall=0)
        deliver(self.a, self.b, wall=60)                       # same meeting
        self.assertEqual(self.b.met["aaaaaa"]["count"], 1)
        deliver(self.a, self.b, wall=60 + nb.NEW_MEETING + 1)  # came back later
        self.assertEqual(self.b.met["aaaaaa"]["count"], 2)

    def test_leaves_around_list_but_stays_met(self):
        deliver(self.a, self.b, now=0)
        self.assertEqual(self.b.around(nb.LOST_AFTER + 1), [])
        self.assertIn("aaaaaa", self.b.met)

    def test_own_packets_ignored(self):
        deliver(self.a, self.a)
        self.assertEqual(self.a.met, {})

    def test_saves_only_on_real_change(self):
        deliver(self.a, self.b, wall=1000)
        self.b.changed = False
        deliver(self.a, self.b, wall=1010)
        self.assertFalse(self.b.changed)  # only "last seen" moved, by 10 s
        deliver(self.a, self.b, wall=1070)
        self.assertTrue(self.b.changed)


class Waves(unittest.TestCase):
    def setUp(self):
        self.a = nb.Node(profile("aaaaaa", nick="Ada"))
        self.b = nb.Node(profile("bbbbbb", nick="Bo"))
        deliver(self.a, self.b)
        deliver(self.b, self.a)

    def test_wave_arrives_once_and_beeps_once(self):
        self.assertEqual(self.a.command({"cmd": "wave", "to": "bbbbbb", "text": "come say hi"}, 0), {"ok": True})
        beeps = deliver(self.a, self.b, now=1, wall=1001) + deliver(self.a, self.b, now=2, wall=1002)
        self.assertEqual(beeps.count(True), 1)
        self.assertEqual([(w["nick"], w["text"]) for w in self.b.waves], [("Ada", "come say hi")])

    def test_wave_stops_after_its_time(self):
        self.a.command({"cmd": "wave", "to": "bbbbbb", "text": "hi"}, 0)
        self.assertEqual(len(self.a.schedule(nb.WAVE_SECONDS + 1)), 6)

    def test_wave_for_someone_else_ignored(self):
        c = nb.Node(profile("cccccc", nick="Cy"))
        deliver(self.a, c)
        self.a.command({"cmd": "wave", "to": "bbbbbb", "text": "hi"}, 0)
        self.assertEqual(deliver(self.a, c, now=1).count(True), 0)
        self.assertEqual(c.waves, [])

    def test_muted_sender_does_not_beep(self):
        self.b.command({"cmd": "mute", "id": "aaaaaa"}, 0)
        self.a.command({"cmd": "wave", "to": "bbbbbb", "text": "spam"}, 0)
        self.assertEqual(deliver(self.a, self.b, now=1).count(True), 0)

    def test_listen_only_refuses_and_unknown_target_refused(self):
        self.assertIn("error", self.a.command({"cmd": "wave", "to": "999999", "text": "x"}, 0))
        self.a.command({"cmd": "listen_only", "on": True}, 0)
        self.assertIn("error", self.a.command({"cmd": "wave", "to": "bbbbbb", "text": "x"}, 0))


class Commands(unittest.TestCase):
    def test_set_card_validates(self):
        n = nb.Node(profile("aaaaaa"))
        self.assertIn("error", n.command({"cmd": "set_card", "nick": "  "}, 0))
        self.assertIn("error", n.command({"cmd": "set_card", "colour": 8}, 0))
        self.assertIn("error", n.command({"cmd": "set_card", "colour": True}, 0))
        self.assertIn("error", n.command({"cmd": "set_card", "avatar": "zz" * 32}, 0))
        self.assertEqual(n.me["rev"], 0)  # nothing applied
        r = n.command({"cmd": "set_card", "nick": "Ada\x1b[31m long name", "colour": 7,
                       "status": "s" * 50, "avatar": "AB" * 32}, 0)
        self.assertEqual((r["me"]["nick"], r["me"]["colour"], len(r["me"]["status"]), r["me"]["avatar"], r["me"]["rev"]),
                         ("Ada[31m lo", 7, 20, "ab" * 32, 1))

    def test_unknown_command(self):
        self.assertIn("error", nb.Node(profile("aaaaaa")).command({"cmd": "rm -rf"}, 0))

    def test_new_profile(self):
        p = nb.new_profile()
        self.assertEqual(len(bytes.fromhex(p["id"])), 3)
        self.assertTrue(p["nick"].startswith("anon-") and len(p["nick"]) <= nb.NICK_MAX)
        self.assertIn(p["colour"], range(nb.COLOURS))


class Files(unittest.TestCase):
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as d:
            n = nb.load_node(d)
            n.met["123456"] = {"nick": "Bo"}
            n.waves.append({"from": "123456", "text": "hi"})
            nb.save_node(d, n)
            m = nb.load_node(d)
            self.assertEqual((m.me, m.met, m.waves), (n.me, n.met, n.waves))
            self.assertFalse(any(f.endswith(".tmp") for f in os.listdir(d)))


@unittest.skipUnless(hasattr(socket, "AF_UNIX") and sys.platform != "win32", "needs Unix sockets")
class Socket(unittest.TestCase):
    def test_request_reply(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.sock")
            server = nb.listen(path)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            node = nb.Node(profile("aaaaaa", nick="Ada"))
            t = threading.Thread(target=lambda: [nb.answer(server, node, 0) for _ in range(2)])
            t.start()
            self.assertEqual(nb.ask({"cmd": "state"}, path)["me"]["nick"], "Ada")
            with socket.socket(socket.AF_UNIX) as s:  # garbage must not kill the service
                s.connect(path)
                s.sendall(b"not json\n")
                self.assertIn("error", json.loads(s.makefile().readline()))
            t.join(5)
            server.close()


class Sound(unittest.TestCase):
    def test_beep_plays_as_sudo_user(self):
        env = {"SUDO_USER": "alice", "SUDO_UID": "1000"}
        self.assertEqual(nb.beep_command("/tmp/b.wav", env, 0),
                         ["runuser", "-u", "alice", "--", "env", "XDG_RUNTIME_DIR=/run/user/1000",
                          "aplay", "-q", "/tmp/b.wav"])
        self.assertEqual(nb.beep_command("/tmp/b.wav", {}, 1000), ["aplay", "-q", "/tmp/b.wav"])
        self.assertEqual(nb.beep_command("/tmp/b.wav", {"SUDO_USER": "x", "SUDO_UID": "1;rm"}, 0),
                         ["aplay", "-q", "/tmp/b.wav"])

    def test_beep_file_is_valid_wav(self):
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
