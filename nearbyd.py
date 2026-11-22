#!/usr/bin/env python3
"""nearbyd: the Nearby background service.

Sends your profile card (nickname, colour, status, 16x16 avatar) over Bluetooth
LE and collects the cards of other CardputerZeros running Nearby. A wave sent
to you beeps. It drives the Bluetooth chip directly over a raw HCI socket:
Linux, CAP_NET_RAW (or root), standard library only. The Nearby app and the
`nearbyd status|card|wave|listen` commands talk to it over a Unix socket.
"""
import argparse
import json
import os
import secrets
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import wave

# ---------- beacon format ----------
# One manufacturer-data AD structure per advert:
#   FF FF | B7 | version<<4 | kind | card id (3) | payload (<= 22)
# 0xFFFF is the Bluetooth SIG company id reserved for testing, so no company owns it.
COMPANY = b"\xff\xff"
MAGIC = 0xB7
VERSION = 1
CARD, STATUS, AVATAR0, AVATAR1, WAVE = 1, 2, 3, 4, 5
NICK_MAX, STATUS_MAX, WAVE_MAX = 10, 20, 18
COLOURS = 8
AVATAR_BYTES = 32  # 16x16 pixels, 1 bit each

ROTATE_SECONDS = 15 * 60  # new random radio address this often
SLOT = 0.5                # seconds each packet is on air before the next one
LOST_AFTER = 10.0         # off the "around" list after this long unheard
NEW_MEETING = 30 * 60     # seen again after this long counts as meeting again
WAVE_SECONDS = 20.0       # keep sending a wave this long (reception drops packets)
# Another app using the radio raw can switch our scanning or advertising off.
QUIET_RESTART = 20.0      # heard no adverts at all this long: restart the radio
REASSERT = 30.0           # switch advertising back on this often
INBOX_MAX = 50

# ---------- HCI ----------
HCI_COMMAND_PKT, HCI_EVENT_PKT = 0x01, 0x04
EVT_CMD_COMPLETE, EVT_CMD_STATUS, EVT_LE_META = 0x0E, 0x0F, 0x3E
LE_ADV_REPORT = 0x02
AD_MANUFACTURER = 0xFF


def _le(ocf):
    return (0x08 << 10) | ocf  # OGF 0x08 = LE controller commands


LE_SET_RANDOM_ADDR = _le(0x05)
LE_SET_ADV_PARAMS = _le(0x06)
LE_SET_ADV_DATA = _le(0x08)
LE_SET_ADV_ENABLE = _le(0x0A)
LE_SET_SCAN_PARAMS = _le(0x0B)
LE_SET_SCAN_ENABLE = _le(0x0C)


class HciError(Exception):
    pass


def command(opcode, params=b""):
    return struct.pack("<BHB", HCI_COMMAND_PKT, opcode, len(params)) + params


def hci_filter():
    """Kernel filter: only events, and only command replies + LE meta events."""
    ev = (1 << EVT_CMD_COMPLETE) | (1 << EVT_CMD_STATUS) | (1 << EVT_LE_META)
    return struct.pack("<IIIH2x", 1 << HCI_EVENT_PKT, ev & 0xFFFFFFFF, ev >> 32, 0)


def ad_structures(data):
    i = 0
    while i < len(data):
        n = data[i]
        if n == 0 or i + 1 + n > len(data):
            return
        yield data[i + 1], data[i + 2:i + 1 + n]
        i += 1 + n


def addr_str(raw):
    return ":".join(f"{b:02X}" for b in reversed(raw))


def adv_reports(packet):
    """Yield (address, ad_data, rssi) from one HCI event; ignore anything else."""
    if len(packet) < 5 or packet[0] != HCI_EVENT_PKT or packet[1] != EVT_LE_META \
            or packet[3] != LE_ADV_REPORT:
        return
    i = 5
    for _ in range(packet[4]):
        if i + 9 > len(packet):
            return
        n = packet[i + 8]
        end = i + 9 + n
        if end >= len(packet):  # data plus the RSSI byte must fit
            return
        rssi = struct.unpack("b", packet[end:end + 1])[0]
        yield addr_str(packet[i + 2:i + 8]), packet[i + 9:end], rssi
        i = end + 1


def command_reply(packet):
    """Return (opcode, status) if this event answers a command, else None."""
    if len(packet) >= 7 and packet[0] == HCI_EVENT_PKT and packet[1] == EVT_CMD_COMPLETE:
        return struct.unpack("<H", packet[4:6])[0], packet[6]
    if len(packet) >= 7 and packet[0] == HCI_EVENT_PKT and packet[1] == EVT_CMD_STATUS:
        return struct.unpack("<H", packet[5:7])[0], packet[3]
    return None


def new_private_address(rand=secrets.token_bytes):
    """Non-resolvable private address: top two bits 00, rest random, not all 0s or 1s."""
    while True:
        a = bytearray(rand(6))
        a[5] &= 0x3F
        if 0 < int.from_bytes(a, "little") < (1 << 46) - 1:
            return bytes(a)


# ---------- packets ----------

def clean(text, limit):
    """Printable ASCII only. Text from strangers must not carry control or escape codes."""
    if isinstance(text, bytes):
        text = text.decode("ascii", "replace")
    return "".join(c for c in text if " " <= c <= "~")[:limit]


def packet(kind, card_id, payload):
    body = COMPANY + bytes([MAGIC, VERSION << 4 | kind]) + card_id + payload
    ad = bytes([len(body) + 1, AD_MANUFACTURER]) + body
    if len(ad) > 31:
        raise ValueError("packet too long")
    return ad


def adv_params(ad):
    """LE Set Advertising Data parameters: length byte + 31 bytes."""
    return bytes([len(ad)]) + ad.ljust(31, b"\0")


def parse(data):
    """(kind, card id hex, payload) for a Nearby advert, else None."""
    for t, v in ad_structures(data):
        if t == AD_MANUFACTURER and len(v) >= 7 and v[:2] == COMPANY and v[2] == MAGIC \
                and v[3] >> 4 == VERSION:
            return v[3] & 0x0F, bytes(v[4:7]).hex(), bytes(v[7:])
    return None


def card_packets(me):
    cid, rev = bytes.fromhex(me["id"]), bytes([me["rev"]])
    av = bytes.fromhex(me["avatar"])
    return [packet(CARD, cid, rev + bytes([me["colour"]]) + me["nick"].encode()),
            packet(STATUS, cid, rev + me["status"].encode()),
            packet(AVATAR0, cid, rev + av[:16]),
            packet(AVATAR1, cid, rev + av[16:])]


def wave_packet(me, to_id, wave_id, text):
    return packet(WAVE, bytes.fromhex(me["id"]), bytes.fromhex(to_id) + bytes([wave_id]) + text.encode())


def schedule(cards, wave_pkt=None):
    """One send cycle. The card goes out most often because it carries the name."""
    c, s, a0, a1 = cards
    seq = [c, s, c, a0, c, a1]
    return [p for x in seq for p in (x, wave_pkt)] if wave_pkt else seq


# ---------- state ----------

def new_profile():
    cid = secrets.token_hex(3)
    return {"id": cid, "nick": "anon-" + cid[:4], "colour": secrets.randbelow(COLOURS),
            "status": "", "avatar": "00" * AVATAR_BYTES, "rev": 0,
            "listen_only": False, "muted": []}


class Node:
    """Everything except the radio and sockets, so it can be tested on any machine."""

    def __init__(self, me, met=None, waves=None):
        self.me = me
        self.met = met or {}      # card id -> {nick, colour, status, avatar, rev, first, last, count}
        self.waves = waves or []  # newest last: {from, nick, text, time, wid}
        self.heard = {}           # card id -> {"last": monotonic, "rssi": [...]}
        self.out = None           # (packet, until) for a wave being sent
        self.wave_id = secrets.randbelow(256)
        self.changed = False

    # --- radio side ---

    def on_advert(self, data, rssi, now, wall):
        """Feed one received advert. Returns True when a wave for us arrived (beep)."""
        p = parse(data)
        if not p or p[1] == self.me["id"]:
            return False
        kind, sender, payload = p
        h = self.heard.setdefault(sender, {"last": 0.0, "rssi": []})
        h["last"], h["rssi"] = now, (h["rssi"] + [rssi])[-5:]
        rec = self.met.get(sender)
        before = dict(rec) if rec else None
        if kind == CARD and len(payload) >= 3:
            rev, colour, nick = payload[0], payload[1] % COLOURS, clean(payload[2:], NICK_MAX)
            if rec is None:
                rec = self.met[sender] = {"nick": nick, "colour": colour, "status": "",
                                          "avatar": "00" * AVATAR_BYTES, "rev": rev,
                                          "first": wall, "last": wall, "count": 1}
            elif wall - rec["last"] > NEW_MEETING:
                rec["count"] += 1
            rec.update(nick=nick, colour=colour, rev=rev)
        if rec is None:
            return False  # status, avatar and waves only count once we have the card
        rec["last"] = wall
        try:
            if kind == STATUS and payload[:1] == bytes([rec["rev"]]):
                rec["status"] = clean(payload[1:], STATUS_MAX)
            elif kind in (AVATAR0, AVATAR1) and len(payload) == 17 and payload[0] == rec["rev"]:
                av = bytearray.fromhex(rec["avatar"])
                av[(kind - AVATAR0) * 16:(kind - AVATAR0 + 1) * 16] = payload[1:]
                rec["avatar"] = av.hex()
            elif kind == WAVE and len(payload) >= 4 and payload[:3].hex() == self.me["id"]:
                self.changed = True
                return self._got_wave(sender, rec, payload[3], clean(payload[4:], WAVE_MAX), wall)
            return False
        finally:
            # Save when something real changed, or "last seen" moved a minute: spares the SD card.
            if before is None or any(before[k] != rec[k] for k in rec if k != "last") \
                    or wall - before["last"] >= 60:
                self.changed = True

    def _got_wave(self, sender, rec, wid, text, wall):
        # A wave repeats for WAVE_SECONDS, so the same one arrives many times.
        if any(w["from"] == sender and w["wid"] == wid and wall - w["time"] < 2 * WAVE_SECONDS
               for w in self.waves):
            return False
        self.waves = (self.waves + [{"from": sender, "nick": rec["nick"], "text": text,
                                     "time": wall, "wid": wid}])[-INBOX_MAX:]
        return sender not in self.me["muted"]

    def schedule(self, now):
        if self.out and now >= self.out[1]:
            self.out = None
        return schedule(card_packets(self.me), self.out[0] if self.out else None)

    def around(self, now):
        """People heard in the last LOST_AFTER seconds, strongest signal first."""
        out = []
        for cid, h in self.heard.items():
            if cid in self.met and now - h["last"] <= LOST_AFTER:
                out.append(dict(self.met[cid], id=cid, rssi=sum(h["rssi"]) // len(h["rssi"])))
        return sorted(out, key=lambda p: -p["rssi"])

    # --- app side ---

    def command(self, req, now):
        cmd = req.get("cmd")
        if cmd == "state":
            met = sorted((dict(r, id=k) for k, r in self.met.items()), key=lambda r: -r["last"])
            return {"me": self.me, "around": self.around(now), "met": met,
                    "waves": self.waves, "sending": self.out is not None}
        if cmd == "set_card":
            return self._set_card(req)
        if cmd == "wave":
            to, text = str(req.get("to", "")), clean(str(req.get("text", "")), WAVE_MAX)
            if self.me["listen_only"]:
                return {"error": "listen-only is on, so nothing is sent"}
            if to not in self.met:
                return {"error": "unknown card id"}
            self.wave_id = (self.wave_id + 1) % 256
            self.out = (wave_packet(self.me, to, self.wave_id, text), now + WAVE_SECONDS)
            return {"ok": True}
        if cmd == "waves_read":  # the app opened the Waves tab: everything up to now is read
            self.me["waves_read"] = max([w["time"] for w in self.waves], default=0)
            self.changed = True
            return {"ok": True}
        if cmd == "listen_only":
            self.me["listen_only"] = bool(req.get("on"))
            self.changed = True
            return {"ok": True}
        if cmd in ("mute", "unmute"):
            cid = str(req.get("id", ""))
            muted = [m for m in self.me["muted"] if m != cid]
            self.me["muted"] = muted + [cid] if cmd == "mute" and cid in self.met else muted
            self.changed = True
            return {"ok": True}
        return {"error": f"unknown command {cmd!r}"}

    def _set_card(self, req):
        new = dict(self.me)
        if "nick" in req:
            new["nick"] = clean(str(req["nick"]), NICK_MAX).strip()
            if not new["nick"]:
                return {"error": "nickname can't be empty"}
        if "colour" in req:
            if type(req["colour"]) is not int or req["colour"] not in range(COLOURS):
                return {"error": f"colour must be 0-{COLOURS - 1}"}
            new["colour"] = req["colour"]
        if "status" in req:
            new["status"] = clean(str(req["status"]), STATUS_MAX)
        if "avatar" in req:
            av = str(req["avatar"]).lower()
            if len(av) != 2 * AVATAR_BYTES or any(c not in "0123456789abcdef" for c in av):
                return {"error": "avatar must be 64 hex characters"}
            new["avatar"] = av
        new["rev"] = (self.me["rev"] + 1) % 256  # tells others their copy is out of date
        self.me = new
        self.changed = True
        return {"ok": True, "me": self.me}


# ---------- files ----------

def data_dir():
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "nearby")


def socket_path():
    run = os.environ.get("XDG_RUNTIME_DIR")
    return os.path.join(run, "nearby.sock") if run else f"/tmp/nearby-{os.getuid()}.sock"


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def save_json(path, value):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(value, f)
    os.replace(tmp, path)  # atomic: a power cut never leaves half a file


def load_node(folder):
    os.makedirs(folder, mode=0o700, exist_ok=True)
    me = load_json(os.path.join(folder, "profile.json"), None)
    if me is None:
        me = new_profile()
        save_json(os.path.join(folder, "profile.json"), me)
    return Node(me, load_json(os.path.join(folder, "met.json"), {}),
                load_json(os.path.join(folder, "waves.json"), []))


def save_node(folder, node):
    for name, value in (("profile", node.me), ("met", node.met), ("waves", node.waves)):
        save_json(os.path.join(folder, name + ".json"), value)
    node.changed = False


# ---------- sound ----------

def make_beep(path):
    rate = 16000
    frames = bytearray()
    for freq in (880, 1320):
        for n in range(rate // 8):
            frames += struct.pack("<h", 9000 if (n * freq * 2 // rate) % 2 else -9000)
        frames += bytes(2 * rate // 20)
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(bytes(frames))


def beep_command(path, env, euid):
    cmd = ["aplay", "-q", path]
    user, uid = env.get("SUDO_USER"), env.get("SUDO_UID", "")
    if euid == 0 and user and uid.isdigit():
        # Under sudo, root can't reach the user's sound server (PipeWire), so play as them.
        cmd = ["runuser", "-u", user, "--", "env", f"XDG_RUNTIME_DIR=/run/user/{uid}"] + cmd
    return cmd


def beep(path):
    if path and shutil.which("aplay"):
        subprocess.Popen(beep_command(path, os.environ, os.geteuid()), stderr=subprocess.DEVNULL)


# ---------- the Bluetooth chip ----------

class Radio:
    def __init__(self, dev):
        self.sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
        self.sock.setsockopt(socket.SOL_HCI, socket.HCI_FILTER, hci_filter())
        self.sock.bind((dev,))

    def send(self, opcode, params=b"", check=True):
        self.sock.send(command(opcode, params))
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            self.sock.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                reply = command_reply(self.sock.recv(260))
            except socket.timeout:
                break
            if reply and reply[0] == opcode:
                if check and reply[1]:
                    raise HciError(f"command 0x{opcode:04X} failed with status 0x{reply[1]:02X}")
                return reply[1]
        raise HciError(f"no reply to command 0x{opcode:04X}")

    def start(self, first_packet, advertise):
        """(Re)start with a fresh random address. The chip refuses an address change mid-scan."""
        self.send(LE_SET_SCAN_ENABLE, b"\0\0", check=False)
        self.send(LE_SET_ADV_ENABLE, b"\0", check=False)
        if advertise:
            self.send(LE_SET_RANDOM_ADDR, new_private_address())
            # 100-150 ms, non-connectable, random own address, all three channels
            self.send(LE_SET_ADV_PARAMS, struct.pack("<HHBBB6sBB", 0xA0, 0xF0, 0x03, 0x01, 0, bytes(6), 0x07, 0))
            self.send(LE_SET_ADV_DATA, adv_params(first_packet))
            self.send(LE_SET_ADV_ENABLE, b"\1")
        # passive scan, 60 ms window every 60 ms, keep duplicates so RSSI stays fresh
        self.send(LE_SET_SCAN_PARAMS, struct.pack("<BHHBB", 0, 0x60, 0x60, 0, 0))
        self.send(LE_SET_SCAN_ENABLE, b"\1\0")

    def set_packet(self, ad):
        self.send(LE_SET_ADV_DATA, adv_params(ad), check=False)

    def stop(self):
        for op, arg in ((LE_SET_ADV_ENABLE, b"\0"), (LE_SET_SCAN_ENABLE, b"\0\0")):
            try:
                self.send(op, arg, check=False)
            except (OSError, HciError):
                pass
        self.sock.close()


# ---------- the service ----------

def listen(path):
    if os.path.exists(path):
        os.unlink(path)  # left over from a crash
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)  # socket is 0600: only this user can talk to the service
    try:
        server.bind(path)
    finally:
        os.umask(old)
    server.listen(4)
    return server


def answer(server, node, now):
    conn, _ = server.accept()
    with conn:
        conn.settimeout(1.0)
        try:
            buf = b""
            while b"\n" not in buf and len(buf) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            reply = node.command(json.loads(buf.decode("utf-8")), now)
        except Exception as e:  # a bad request must never take the service down
            reply = {"error": f"bad request: {e}"}
        try:
            conn.sendall(json.dumps(reply).encode() + b"\n")
        except OSError:
            pass


def serve(dev, quiet):
    folder = data_dir()
    node = load_node(folder)
    radio = Radio(dev)
    server = listen(socket_path())
    sound = None
    if not quiet:
        fd, sound = tempfile.mkstemp(suffix=".wav")
        os.close(fd)
        make_beep(sound)
        os.chmod(sound, 0o644)  # readable by the sudo user who plays it
    rotate_at = slot_at = save_at = reassert_at = 0.0
    heard_at = time.monotonic()
    advertising = None
    slot = 0
    print(f"nearbyd: card {node.me['id']} ({node.me['nick']}), socket {socket_path()}", flush=True)
    try:
        while True:
            now = time.monotonic()
            want = not node.me["listen_only"]
            if now - heard_at > QUIET_RESTART:
                print("nearbyd: radio went quiet (another app?), restarting it", flush=True)
                rotate_at, heard_at = now, now
            if now >= rotate_at or want != advertising:
                radio.start(node.schedule(now)[0], want)
                advertising, rotate_at, reassert_at = want, now + ROTATE_SECONDS, now + REASSERT
            if want and now >= reassert_at:
                radio.send(LE_SET_ADV_ENABLE, b"\1", check=False)
                reassert_at = now + REASSERT
            if want and now >= slot_at:
                seq = node.schedule(now)
                radio.set_packet(seq[slot % len(seq)])
                slot, slot_at = slot + 1, now + SLOT
            ready = select.select([radio.sock, server], [], [], 0.1)[0]
            if radio.sock in ready:
                for _, data, rssi in adv_reports(radio.sock.recv(260)):
                    heard_at = now
                    if node.on_advert(data, rssi, now, time.time()) and not quiet:
                        beep(sound)
            if server in ready:
                answer(server, node, now)
            if node.changed and now >= save_at:
                save_node(folder, node)
                save_at = now + 5  # at most every 5 s: spares the SD card
    finally:
        radio.stop()
        save_node(folder, node)
        server.close()
        os.unlink(socket_path())
        if sound:
            os.remove(sound)


# ---------- command line ----------

def ask(req, path=None):
    """Send one request to the running service and return its reply."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(3)
        s.connect(path or socket_path())
        s.sendall(json.dumps(req).encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf.decode("utf-8"))


def ago(seconds):
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= n:
            return f"{int(seconds // n)}{unit} ago"
    return "just now"


def show_status(state, wall):
    me = state["me"]
    print(f"Me: {me['nick']} (card {me['id']}, colour {me['colour']}) \"{me['status']}\""
          + ("  [listen-only]" if me["listen_only"] else ""))
    print(f"Around now: {len(state['around'])}")
    for p in state["around"]:
        print(f"  {p['nick']:<10} {p['rssi']:>4} dBm  \"{p['status']}\"")
    print(f"Met: {len(state['met'])}")
    for p in state["met"]:
        print(f"  {p['nick']:<10} x{p['count']:<3} last {ago(wall - p['last'])}  card {p['id']}")
    print(f"Waves: {len(state['waves'])}")
    for w in state["waves"][-5:]:
        print(f"  from {w['nick']}: \"{w['text']}\" ({ago(wall - w['time'])})")


def _stop(*_):
    # Ignore repeats (sudo passes the same signal on) so the save in `finally` can finish.
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, signal.SIG_IGN)
    raise KeyboardInterrupt


def main(argv=None):
    ap = argparse.ArgumentParser(prog="nearbyd", description="Nearby background service.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run the service")
    run.add_argument("--hci", type=int, default=0, help="Bluetooth adapter number (default 0)")
    run.add_argument("--quiet", action="store_true", help="no beep for waves")
    sub.add_parser("status", help="show your card, who is around, who you met, waves")
    card = sub.add_parser("card", help="change your card")
    card.add_argument("--nick")
    card.add_argument("--colour", type=int)
    card.add_argument("--status")
    wv = sub.add_parser("wave", help="wave at someone you have met")
    wv.add_argument("nick")
    wv.add_argument("text", nargs="?", default="")
    lo = sub.add_parser("listen", help="listen-only on/off (on = send nothing)")
    lo.add_argument("on", choices=["on", "off"])
    args = ap.parse_args(argv)

    if args.cmd == "run":
        if not sys.platform.startswith("linux"):
            sys.exit("nearbyd needs Linux (it talks to the Bluetooth chip directly).")
        signal.signal(signal.SIGINT, _stop)  # even when a background shell ignores Ctrl+C
        signal.signal(signal.SIGTERM, _stop)
        if signal.getsignal(signal.SIGHUP) is not signal.SIG_IGN:  # respect nohup
            signal.signal(signal.SIGHUP, _stop)
        try:
            serve(args.hci, args.quiet)
        except KeyboardInterrupt:
            print("nearbyd: stopped, beacon off.", flush=True)
        except PermissionError:
            sys.exit("nearbyd needs CAP_NET_RAW (or root) to drive Bluetooth directly.")
        except OSError as e:
            sys.exit(f"Bluetooth problem ({e}). Is it on? Try: sudo rfkill unblock bluetooth && bluetoothctl power on")
        except HciError as e:
            sys.exit(f"The Bluetooth chip said no: {e}. Another app may be scanning; close it and retry.")
        return

    try:
        if args.cmd == "status":
            show_status(ask({"cmd": "state"}), time.time())
            return
        if args.cmd == "card":
            req = {k: v for k, v in (("nick", args.nick), ("colour", args.colour), ("status", args.status))
                   if v is not None}
            reply = ask(dict(req, cmd="set_card"))
        elif args.cmd == "wave":
            met = ask({"cmd": "state"})["met"]
            match = [p["id"] for p in met if p["nick"].lower() == args.nick.lower() or p["id"] == args.nick]
            if len(match) != 1:
                sys.exit(f"No single person called {args.nick!r} in your Met list.")
            reply = ask({"cmd": "wave", "to": match[0], "text": args.text})
        else:
            reply = ask({"cmd": "listen_only", "on": args.on == "on"})
    except (FileNotFoundError, ConnectionRefusedError):
        sys.exit("nearbyd isn't running.")
    sys.exit(reply["error"] if "error" in reply else 0)


if __name__ == "__main__":
    main()
