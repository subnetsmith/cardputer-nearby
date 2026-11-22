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
    key, pub = nb.new_keypair()
    return {"id": cid, "nick": nick, "colour": colour, "status": status, "avatar": avatar,
            "rev": rev, "listen_only": False, "muted": [], "key": key, "pub": pub, "tx": 0}


def deliver(sender, receiver, now=0.0, wall=1000.0, rssi=-50):
    """Put every packet in sender's current cycle on air to receiver; return beeps."""
    return [receiver.on_advert(p, rssi, now, wall) for p in sender.schedule(now)]


def fragments(node):
    return [p for p in node.out[0]] if node.out else []


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
    def test_everything_fits_in_31_bytes(self):
        a = nb.Node(profile("abcdef", nick="x" * 10, status="y" * 20, avatar="ff" * 32))
        b = nb.Node(profile("123456"))
        deliver(b, a)
        self.assertEqual(a.command({"cmd": "text", "to": "123456", "text": "w" * 60}, 0), {"ok": True})
        self.assertEqual(len(fragments(a)), 4)  # 40 characters + 16-byte tag = 56 bytes
        for p in a.schedule(0):
            self.assertLessEqual(len(p), 31)
            self.assertEqual(len(nb.adv_params(p)), 32)

    def test_round_trip(self):
        p = nb.packet(nb.STATUS, bytes.fromhex("a1b2c3"), b"\x07hello")
        self.assertEqual(nb.parse(p), (nb.STATUS, "a1b2c3", b"\x07hello"))

    def test_foreign_adverts_ignored(self):
        self.assertIsNone(nb.parse(b""))
        self.assertIsNone(nb.parse(bytes([2, 0x01, 0x06])))                        # flags only
        self.assertIsNone(nb.parse(bytes([8, 0xFF, 0x4C, 0x00, 1, 2, 3, 4, 5])))   # someone else's company id
        self.assertIsNone(nb.parse(bytes([9, 0xFF, 0xFF, 0xFF, 0xB6, 0x21, 1, 2, 3])))  # wrong magic
        self.assertIsNone(nb.parse(bytes([9, 0xFF, 0xFF, 0xFF, 0xB7, 0x11, 1, 2, 3])))  # version 1 (Nearby 1.1)
        self.assertIsNone(nb.parse(bytes([5, 0xFF, 0xFF, 0xFF, 0xB7, 0x21])))      # too short

    def test_schedule(self):
        cards = ["C", "S", "A0", "A1", "K0", "K1"]
        self.assertEqual(nb.schedule(cards), ["C", "S", "C", "A0", "C", "A1", "C", "K0", "C", "K1"])
        with_text = nb.schedule(cards, ["F0", "F1", "F2", "F3"])
        self.assertEqual(with_text[:6], ["C", "F0", "F1", "S", "F2", "F3"])
        self.assertEqual(sum(p.startswith("F") for p in with_text), 20)  # two of every three slots

    def test_clean_strips_control_and_escape_codes(self):
        self.assertEqual(nb.clean(b"hi\x1b[2J\x07there\xff", 20), "hi[2Jthere")
        self.assertEqual(nb.clean("a" * 30, 10), "a" * 10)


class Swap(unittest.TestCase):
    def setUp(self):
        self.a = nb.Node(profile("aaaaaa", nick="Ada", colour=2, status="hello", avatar="0f" * 32))
        self.b = nb.Node(profile("bbbbbb", nick="Bo"))

    def test_full_card_and_key_arrive(self):
        deliver(self.a, self.b, wall=500.0)
        rec = self.b.met["aaaaaa"]
        self.assertEqual((rec["nick"], rec["colour"], rec["status"], rec["avatar"], rec["pub"]),
                         ("Ada", 2, "hello", "0f" * 32, self.a.me["pub"]))
        self.assertEqual((rec["first"], rec["last"], rec["count"]), (500.0, 500.0, 1))
        self.assertEqual([p["nick"] for p in self.b.around(0)], ["Ada"])

    def test_status_before_card_is_ignored(self):
        self.b.on_advert(nb.card_packets(self.a.me)[1], -50, 0, 0)
        self.assertNotIn("aaaaaa", self.b.met)

    def test_edit_bumps_rev_and_old_parts_are_ignored(self):
        old_status = nb.card_packets(self.a.me)[1]
        deliver(self.a, self.b)
        self.a.command({"cmd": "set_card", "status": "new"}, 0)
        self.b.on_advert(nb.card_packets(self.a.me)[0], -50, 1, 1001)
        self.b.on_advert(old_status, -50, 1, 1001)
        self.assertEqual(self.b.met["aaaaaa"]["status"], "hello")
        self.b.on_advert(nb.card_packets(self.a.me)[1], -50, 1, 1001)
        self.assertEqual(self.b.met["aaaaaa"]["status"], "new")

    def test_meeting_counts(self):
        deliver(self.a, self.b, wall=0)
        deliver(self.a, self.b, wall=60)
        self.assertEqual(self.b.met["aaaaaa"]["count"], 1)
        deliver(self.a, self.b, wall=60 + nb.NEW_MEETING + 1)
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
        self.assertFalse(self.b.changed)
        deliver(self.a, self.b, wall=1070)
        self.assertTrue(self.b.changed)

    def test_safety_codes_match_on_both_sides(self):
        deliver(self.a, self.b)
        deliver(self.b, self.a)
        code_on_a = self.a.command({"cmd": "state"}, 0)["met"][0]["code"]
        code_on_b = self.b.command({"cmd": "state"}, 0)["met"][0]["code"]
        self.assertEqual(code_on_a, code_on_b)
        self.assertRegex(code_on_a, r"^\d{3} \d{3}$")

    def test_private_key_never_leaves_the_service(self):
        st = self.a.command({"cmd": "state"}, 0)
        self.assertNotIn("key", st["me"])
        self.assertNotIn(self.a.me["key"], json.dumps(st))
        self.assertNotIn("key", self.a.command({"cmd": "set_card", "nick": "Ada2"}, 0)["me"])


class Texts(unittest.TestCase):
    def setUp(self):
        self.a = nb.Node(profile("aaaaaa", nick="Ada"))
        self.b = nb.Node(profile("bbbbbb", nick="Bo"))
        deliver(self.a, self.b)
        deliver(self.b, self.a)

    def send(self, text="come say hi", to="bbbbbb", node=None):
        node = node or self.a
        self.assertEqual(node.command({"cmd": "text", "to": to, "text": text}, 0), {"ok": True})
        return fragments(node)

    def feed(self, frags, node=None, wall=2000.0):
        node = node or self.b
        return [node.on_advert(p, -50, 1, wall) for p in frags]

    def test_text_arrives_once_and_beeps_once(self):
        frags = self.send()
        beeps = self.feed(frags) + self.feed(frags) + deliver(self.a, self.b, now=2)
        self.assertEqual(beeps.count(True), 1)
        self.assertEqual([(w["nick"], w["text"]) for w in self.b.waves], [("Ada", "come say hi")])
        self.assertEqual(self.a.sent[-1]["text"], "come say hi")

    def test_fragments_in_any_order(self):
        frags = self.send("x" * 40)
        self.assertEqual(self.feed(list(reversed(frags))).count(True), 1)
        self.assertEqual(self.b.waves[0]["text"], "x" * 40)

    def test_missing_fragment_means_no_text_yet(self):
        frags = self.send("x" * 40)
        self.feed(frags[:-1])
        self.assertEqual(self.b.waves, [])
        self.assertEqual(self.feed(frags[-1:]).count(True), 1)

    def test_ciphertext_does_not_contain_the_words(self):
        frags = self.send("meet at the library")
        self.assertNotIn(b"library", b"".join(frags))

    def test_altered_text_is_rejected(self):
        frags = self.send()
        bad = bytearray(frags[0])
        bad[-1] ^= 0x01
        self.feed([bytes(bad)] + frags[1:])
        self.assertEqual(self.b.waves, [])
        self.assertEqual(self.feed(frags).count(True), 1)  # the real one still gets through afterwards

    def test_replay_is_ignored(self):
        frags = self.send()
        self.feed(frags)
        self.b.waves.clear()
        self.assertEqual(self.feed(frags, wall=9999).count(True), 0)  # recorded and replayed later
        self.assertEqual(self.b.waves, [])

    def test_counter_rises_and_survives_restart(self):
        self.send("one")
        self.send("two")
        self.assertEqual(self.a.me["tx"], 2)
        self.assertTrue(self.a.urgent)  # the counter must hit the disk before the text is sent

    def test_text_for_someone_else_is_unreadable_to_them(self):
        c = nb.Node(profile("cccccc", nick="Cy"))
        deliver(self.a, c)
        frags = self.send()
        self.assertEqual(self.feed(frags, node=c).count(True), 0)
        self.assertEqual(c.waves, [])

    def test_forged_text_from_impostor_is_rejected(self):
        # Mallory copies Ada's card id but has her own key, so she can't make a valid text for Bo.
        mallory = nb.Node(profile("aaaaaa", nick="Ada"))
        deliver(self.b, mallory)
        self.feed(self.send("send me money", node=mallory))
        self.assertEqual(self.b.waves, [])

    def test_impostor_key_is_flagged_and_texting_refused(self):
        mallory = nb.Node(profile("aaaaaa", nick="Ada"))
        deliver(mallory, self.b)
        self.assertTrue(self.b.met["aaaaaa"]["impostor"])
        self.assertEqual(self.b.met["aaaaaa"]["pub"], self.a.me["pub"])  # the first key stays pinned
        reply = self.b.command({"cmd": "text", "to": "aaaaaa", "text": "hi"}, 0)
        self.assertIn("copying", reply["error"])
        self.assertFalse(self.b.command({"cmd": "state"}, 0)["met"][0]["can_text"])

    def test_no_key_yet(self):
        c = nb.Node(profile("cccccc", nick="Cy"))
        c.on_advert(nb.card_packets(self.a.me)[0], -50, 0, 0)  # only the card arrived
        reply = c.command({"cmd": "text", "to": "aaaaaa", "text": "hi"}, 0)
        self.assertIn("key hasn't arrived", reply["error"])

    def test_muted_sender_does_not_beep(self):
        self.b.command({"cmd": "mute", "id": "aaaaaa"}, 0)
        self.assertEqual(self.feed(self.send()).count(True), 0)
        self.assertEqual(len(self.b.waves), 1)  # still kept, just quiet

    def test_refusals(self):
        self.assertIn("error", self.a.command({"cmd": "text", "to": "999999", "text": "x"}, 0))
        self.assertIn("error", self.a.command({"cmd": "text", "to": "bbbbbb", "text": "   "}, 0))
        self.a.command({"cmd": "listen_only", "on": True}, 0)
        self.assertIn("error", self.a.command({"cmd": "text", "to": "bbbbbb", "text": "x"}, 0))
        self.assertEqual(self.a.me["tx"], 0)  # refusals never use up a counter

    def test_text_stops_after_its_time(self):
        self.send()
        self.assertEqual(len(self.a.schedule(nb.TEXT_SECONDS + 1)), 10)

    def receipts(self, node=None):
        node = node or self.b
        return [p for p in node.schedule(1) if nb.parse(p)[0] == nb.ACK]

    def test_receipt_stops_resending_and_marks_delivered(self):
        self.feed(self.send())
        acks = self.receipts()
        self.assertTrue(acks)
        self.assertFalse(self.a.sent[-1]["delivered"])
        for p in acks:
            self.a.on_advert(p, -50, 2, 2001)
        self.assertIsNone(self.a.out)
        self.assertTrue(self.a.sent[-1]["delivered"])
        self.assertEqual(len(self.a.schedule(3)), 10)  # back to just the card

    def test_forged_receipt_is_ignored(self):
        self.send()
        real_tag = nb.receipt_tag(b"\0" * 32, "aaaaaa", "bbbbbb", 1)  # wrong key: Mallory doesn't have theirs
        fake = nb.packet(nb.ACK, bytes.fromhex("bbbbbb"), bytes.fromhex("aaaaaa") + (1).to_bytes(3, "big") + real_tag)
        self.a.on_advert(fake, -50, 2, 2001)
        self.assertIsNotNone(self.a.out)
        self.assertFalse(self.a.sent[-1]["delivered"])

    def test_missed_receipt_is_sent_again(self):
        frags = self.send()
        self.feed(frags)
        self.b.receipts.clear()   # pretend it timed out before Ada heard it
        self.feed(frags)           # Ada is still resending
        self.assertTrue(self.receipts())

    def test_listen_only_receiver_sends_no_receipt(self):
        self.b.command({"cmd": "listen_only", "on": True}, 0)
        self.feed(self.send())
        self.assertEqual(len(self.b.waves), 1)
        self.assertEqual(self.b.receipts, {})

    def test_fragment_flood_is_bounded(self):
        for counter in range(1, 200):
            payload = bytes.fromhex("bbbbbb") + counter.to_bytes(3, "big") + bytes([0x02]) + b"x" * 15
            self.b.on_advert(nb.packet(nb.TEXT, bytes.fromhex("aaaaaa"), payload), -50, 1, 2000)
        self.assertLessEqual(len(self.b.partial), nb.PARTIAL_MAX)


class Commands(unittest.TestCase):
    def test_set_card_validates(self):
        n = nb.Node(profile("aaaaaa"))
        self.assertIn("error", n.command({"cmd": "set_card", "nick": "  "}, 0))
        self.assertIn("error", n.command({"cmd": "set_card", "colour": 8}, 0))
        self.assertIn("error", n.command({"cmd": "set_card", "colour": True}, 0))
        self.assertIn("error", n.command({"cmd": "set_card", "avatar": "zz" * 32}, 0))
        self.assertEqual(n.me["rev"], 0)
        r = n.command({"cmd": "set_card", "nick": "Ada\x1b[31m long name", "colour": 7,
                       "status": "s" * 50, "avatar": "AB" * 32}, 0)
        self.assertEqual((r["me"]["nick"], r["me"]["colour"], len(r["me"]["status"]), r["me"]["avatar"], r["me"]["rev"]),
                         ("Ada[31m lo", 7, 20, "ab" * 32, 1))

    def test_waves_read_marks_up_to_newest(self):
        n = nb.Node(profile("aaaaaa"), waves=[{"from": "b", "time": 5.0}, {"from": "b", "time": 9.0}])
        self.assertEqual(n.command({"cmd": "waves_read"}, 0), {"ok": True})
        self.assertEqual(n.me["waves_read"], 9.0)

    def test_background_setting(self):
        n = nb.Node(profile("aaaaaa"))
        self.assertTrue(n.me.get("background", True))   # on unless switched off; old cards have no field
        n.command({"cmd": "background", "on": False}, 0)
        self.assertFalse(n.me["background"])
        self.assertFalse(n.command({"cmd": "state"}, 0)["me"]["background"])
        self.assertTrue(nb.new_profile()["background"])

    def test_client_finds_the_right_socket(self):
        env = dict(os.environ)
        try:
            with tempfile.TemporaryDirectory() as d:
                os.environ.pop("NEARBY_SOCKET", None)
                os.environ["XDG_RUNTIME_DIR"] = d
                self.assertEqual(nb.client_path(), nb.SYSTEM_SOCKET)       # installed: systemd's socket
                open(os.path.join(d, "nearby.sock"), "w").close()
                self.assertEqual(nb.client_path(), os.path.join(d, "nearby.sock"))  # a hand-started service
                os.environ["NEARBY_SOCKET"] = "/x/y.sock"
                self.assertEqual(nb.client_path(), "/x/y.sock")
        finally:
            os.environ.clear()
            os.environ.update(env)

    def test_not_socket_activated_without_systemd(self):
        env = dict(os.environ)
        try:
            os.environ.pop("LISTEN_PID", None)
            self.assertIsNone(nb.systemd_socket())
            os.environ.update(LISTEN_PID="1", LISTEN_FDS="1")  # meant for another process
            self.assertIsNone(nb.systemd_socket())
        finally:
            os.environ.clear()
            os.environ.update(env)

    def test_unknown_command(self):
        self.assertIn("error", nb.Node(profile("aaaaaa")).command({"cmd": "rm -rf"}, 0))

    def test_new_profile(self):
        p = nb.new_profile()
        self.assertEqual(len(bytes.fromhex(p["id"])), 3)
        self.assertTrue(p["nick"].startswith("anon-") and len(p["nick"]) <= nb.NICK_MAX)
        self.assertIn(p["colour"], range(nb.COLOURS))
        self.assertEqual((len(p["key"]), len(p["pub"]), p["tx"]), (64, 64, 0))


class Files(unittest.TestCase):
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as d:
            n = nb.load_node(d)
            n.met["123456"] = {"nick": "Bo"}
            n.waves.append({"from": "123456", "text": "hi"})
            n.sent.append({"to": "123456", "text": "yo"})
            nb.save_node(d, n)
            m = nb.load_node(d)
            self.assertEqual((m.me, m.met, m.waves, m.sent), (n.me, n.met, n.waves, n.sent))
            self.assertFalse(any(f.endswith(".tmp") for f in os.listdir(d)))

    def test_old_card_gets_a_key(self):
        with tempfile.TemporaryDirectory() as d:
            old = profile("abcdef", nick="Ada")
            for k in ("key", "pub", "tx"):
                del old[k]
            nb.save_json(os.path.join(d, "profile.json"), old)
            me = nb.load_node(d).me
            self.assertEqual((me["nick"], me["id"], me["tx"], len(me["pub"])), ("Ada", "abcdef", 0, 64))
            self.assertEqual(nb.load_node(d).me["key"], me["key"])  # saved, not regenerated

    @unittest.skipUnless(sys.platform.startswith("linux"), "file modes need Linux")
    def test_files_are_owner_only(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.path.join(d, "waves.json")  # left readable by 1.1
            with open(old, "w") as f:
                f.write("[]")
            os.chmod(old, 0o644)
            nb.load_node(d)
            self.assertEqual(os.stat(old).st_mode & 0o777, 0o600)
            nb.save_node(d, nb.load_node(d))
            for f in os.listdir(d):
                self.assertEqual(os.stat(os.path.join(d, f)).st_mode & 0o777, 0o600, f)


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
