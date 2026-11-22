#!/usr/bin/env python3
"""nearbyd: the Nearby background service.

Sends your profile card (nickname, colour, status, 16x16 avatar, public key)
over Bluetooth LE and collects the cards of other CardputerZeros running
Nearby. Texts between two people are end-to-end encrypted (X25519 +
ChaCha20-Poly1305 from the `cryptography` package); a text for you beeps.
It drives the Bluetooth chip directly over a raw HCI socket: Linux and
CAP_NET_RAW (or root). The Nearby app and the
`nearbyd status|card|text|listen` commands talk to it over a Unix socket.
"""
import argparse
import hashlib
import hmac
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

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------- beacon format ----------
# One manufacturer-data AD structure per advert:
#   FF FF | B7 | version<<4 | kind | card id (3) | payload (<= 22)
# 0xFFFF is the Bluetooth SIG company id reserved for testing, so no company owns it.
COMPANY = b"\xff\xff"
MAGIC = 0xB7
VERSION = 2  # 2 added public keys and encrypted texts; version 1 devices are ignored
CARD, STATUS, AVATAR0, AVATAR1, TEXT, KEY0, KEY1, ACK = 1, 2, 3, 4, 5, 6, 7, 8
NICK_MAX, STATUS_MAX, TEXT_MAX = 10, 20, 40
COLOURS = 8
AVATAR_BYTES = 32  # 16x16 pixels, 1 bit each
# A text fragment: to (3) | counter (3) | index<<4 | count | ciphertext chunk
FRAG = 22 - 7
PARTIAL_MAX = 32   # half-received texts kept at once (bounds memory if someone floods fragments)

ROTATE_SECONDS = 15 * 60  # new random radio address this often
SLOT = 0.5                # seconds each packet is on air before the next one
LOST_AFTER = 30.0         # off the "around" list after this long unheard (reception has long gaps)
NEW_MEETING = 30 * 60     # seen again after this long counts as meeting again
TEXT_SECONDS = 120.0      # keep resending a text until its receipt arrives, at most this long
ACK_SECONDS = 30.0        # keep sending a receipt this long
IDLE_EXIT = 60.0          # with Background off: stop this long after the app's last request
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
    av, pub = bytes.fromhex(me["avatar"]), bytes.fromhex(me["pub"])
    return [packet(CARD, cid, rev + bytes([me["colour"]]) + me["nick"].encode()),
            packet(STATUS, cid, rev + me["status"].encode()),
            packet(AVATAR0, cid, rev + av[:16]),
            packet(AVATAR1, cid, rev + av[16:]),
            packet(KEY0, cid, pub[:16]),
            packet(KEY1, cid, pub[16:])]


def schedule(cards, text=()):
    """One send cycle. The card goes out most often because it carries the name.
    While a text or receipts are going out, two of every three slots carry them."""
    c, s, a0, a1, k0, k1 = cards
    seq = [c, s, c, a0, c, a1, c, k0, c, k1]
    if not text:
        return seq
    out, n = [], 0
    for p in seq:
        out += [p, text[n % len(text)], text[(n + 1) % len(text)]]
        n += 2
    return out


# ---------- encryption ----------
# Each pair of people shares one key: X25519 between their card keys, through HKDF.
# A text's nonce is sender id | recipient id | the sender's text counter, which never
# repeats (it is saved before the text goes on air), so no nonce is ever reused.

def new_keypair():
    k = X25519PrivateKey.generate()
    return k.private_bytes_raw().hex(), k.public_key().public_bytes_raw().hex()


def pair_key(my_key_hex, my_pub_hex, their_pub_hex):
    """The shared 32-byte key for this pair, the same from both sides. ValueError for a bad key."""
    shared = X25519PrivateKey.from_private_bytes(bytes.fromhex(my_key_hex)).exchange(
        X25519PublicKey.from_public_bytes(bytes.fromhex(their_pub_hex)))
    lo, hi = sorted([bytes.fromhex(my_pub_hex), bytes.fromhex(their_pub_hex)])
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"nearby text v2" + lo + hi).derive(shared)


def safety_code(pub_a_hex, pub_b_hex):
    """Six digits both people see the same; compare them in person to rule out a faked card."""
    lo, hi = sorted([bytes.fromhex(pub_a_hex), bytes.fromhex(pub_b_hex)])
    n = int.from_bytes(hashlib.sha256(b"nearby safety" + lo + hi).digest()[:4], "big") % 1_000_000
    return f"{n // 1000:03d} {n % 1000:03d}"


def _header(sender_hex, to_hex, counter):
    return bytes.fromhex(sender_hex) + bytes.fromhex(to_hex) + counter.to_bytes(3, "big")


def text_packets(me, to_hex, counter, text, key):
    """Encrypt a text and cut it into beacon fragments."""
    head = _header(me["id"], to_hex, counter)
    ct = ChaCha20Poly1305(key).encrypt(head + b"\0\0\0", text.encode(), b"nearby2" + head)
    chunks = [ct[i:i + FRAG] for i in range(0, len(ct), FRAG)]
    return [packet(TEXT, bytes.fromhex(me["id"]), head[3:] + bytes([i << 4 | len(chunks)]) + c)
            for i, c in enumerate(chunks)]


def receipt_tag(key, sender_hex, to_hex, counter):
    """8 bytes only the two people in this chat can make: a receipt nobody else can fake."""
    return hmac.new(key, b"nearby ack" + _header(sender_hex, to_hex, counter), hashlib.sha256).digest()[:8]


def receipt_packet(me, sender_hex, counter, key):
    """Sent by the receiver of a text: "I have text <counter> from <sender>"."""
    return packet(ACK, bytes.fromhex(me["id"]), bytes.fromhex(sender_hex) + counter.to_bytes(3, "big")
                  + receipt_tag(key, sender_hex, me["id"], counter))


def open_text(key, sender_hex, to_hex, counter, ct):
    """The text, or None if it was altered or isn't for this key."""
    head = _header(sender_hex, to_hex, counter)
    try:
        return ChaCha20Poly1305(key).decrypt(head + b"\0\0\0", ct, b"nearby2" + head)
    except InvalidTag:
        return None


# ---------- state ----------

def new_profile():
    cid = secrets.token_hex(3)
    key, pub = new_keypair()
    return {"id": cid, "nick": "anon-" + cid[:4], "colour": secrets.randbelow(COLOURS),
            "status": "", "avatar": "00" * AVATAR_BYTES, "rev": 0,
            "listen_only": False, "background": True, "muted": [], "key": key, "pub": pub, "tx": 0}


class Node:
    """Everything except the radio and sockets, so it can be tested on any machine."""

    def __init__(self, me, met=None, waves=None, sent=None):
        self.me = me
        self.met = met or {}      # card id -> {nick, colour, status, avatar, rev, first, last, count, pub, rx}
        self.waves = waves or []  # texts received, newest last: {from, nick, text, time, wid}
        self.sent = sent or []    # texts sent, newest last: {to, nick, text, time}
        self.heard = {}           # card id -> {"last": monotonic, "rssi": [...]}
        self.partial = {}         # (sender, counter) -> {"n", "parts", "t"}: texts still arriving
        self.out = None           # (fragments, until, to, counter) for the text being sent
        self.receipts = {}        # (sender, counter) -> (packet, until): receipts we are sending
        self.changed = False
        self.urgent = False       # save before anything else goes on air (the text counter)

    # --- radio side ---

    def on_advert(self, data, rssi, now, wall):
        """Feed one received advert. Returns True when a text for us arrived (beep)."""
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
            return False  # status, avatar, key and texts only count once we have the card
        rec["last"] = wall
        try:
            if kind == STATUS and payload[:1] == bytes([rec["rev"]]):
                rec["status"] = clean(payload[1:], STATUS_MAX)
            elif kind in (AVATAR0, AVATAR1) and len(payload) == 17 and payload[0] == rec["rev"]:
                av = bytearray.fromhex(rec["avatar"])
                av[(kind - AVATAR0) * 16:(kind - AVATAR0 + 1) * 16] = payload[1:]
                rec["avatar"] = av.hex()
            elif kind in (KEY0, KEY1) and len(payload) == 16:
                self._got_key_half(rec, kind - KEY0, payload.hex())
            elif kind == ACK and len(payload) == 14 and payload[:3].hex() == self.me["id"]:
                self._got_receipt(sender, rec, int.from_bytes(payload[3:6], "big"), payload[6:])
            elif kind == TEXT and len(payload) > 7 and payload[:3].hex() == self.me["id"]:
                return self._got_fragment(sender, rec, payload, now, wall)
            return False
        finally:
            # Save when something real changed, or "last seen" moved a minute: spares the SD card.
            if before is None or any(before.get(k) != rec[k] for k in rec if k != "last") \
                    or wall - before["last"] >= 60:
                self.changed = True

    def _got_key_half(self, rec, half, hexpart):
        if rec.get("pub"):
            # The first key seen for a card is pinned. A real card's key never changes,
            # so a different one means someone is copying this card id.
            if rec["pub"][half * 32:(half + 1) * 32] != hexpart:
                rec["impostor"] = True
            return
        parts = rec.setdefault("pubparts", ["", ""])
        parts[half] = hexpart
        if all(parts):
            try:
                X25519PublicKey.from_public_bytes(bytes.fromhex(parts[0] + parts[1]))
                rec["pub"] = parts[0] + parts[1]
            except ValueError:
                pass
            del rec["pubparts"]

    def _got_fragment(self, sender, rec, payload, now, wall):
        counter = int.from_bytes(payload[3:6], "big")
        idx, n = payload[6] >> 4, payload[6] & 0x0F
        if not n or idx >= n:
            return False
        if counter <= rec.get("rx", 0):
            # Already have it (replays land here too). If it's the latest, they may have missed
            # our receipt, so keep sending one.
            if counter == rec.get("rx") and rec.get("pub"):
                self._send_receipt(sender, rec, counter, now)
            return False
        slot = self.partial.get((sender, counter))
        if slot is None or slot["n"] != n:
            if len(self.partial) >= PARTIAL_MAX:
                del self.partial[min(self.partial, key=lambda k: self.partial[k]["t"])]
            slot = self.partial[(sender, counter)] = {"n": n, "parts": {}, "t": now}
        slot["parts"][idx] = bytes(payload[7:])
        if len(slot["parts"]) < n:
            return False
        del self.partial[(sender, counter)]
        if not rec.get("pub"):
            return False  # can't check it without their key; they keep resending, so try again later
        try:
            key = pair_key(self.me["key"], self.me["pub"], rec["pub"])
        except ValueError:
            return False
        plain = open_text(key, sender, self.me["id"], counter, b"".join(slot["parts"][i] for i in range(n)))
        if plain is None:
            return False  # altered, or forged by someone without their key
        rec["rx"] = counter
        self._send_receipt(sender, rec, counter, now)
        self.changed = True
        self.waves = (self.waves + [{"from": sender, "nick": rec["nick"], "time": wall, "wid": counter,
                                     "text": clean(plain.decode("utf-8", "replace"), TEXT_MAX)}])[-INBOX_MAX:]
        return sender not in self.me["muted"]

    def _send_receipt(self, sender, rec, counter, now):
        try:
            key = pair_key(self.me["key"], self.me["pub"], rec["pub"])
        except ValueError:
            return
        if not self.me["listen_only"]:
            self.receipts[(sender, counter)] = (receipt_packet(self.me, sender, counter, key), now + ACK_SECONDS)

    def _got_receipt(self, sender, rec, counter, tag):
        if not self.out or self.out[2] != sender or self.out[3] != counter or not rec.get("pub"):
            return
        try:
            key = pair_key(self.me["key"], self.me["pub"], rec["pub"])
        except ValueError:
            return
        if hmac.compare_digest(tag, receipt_tag(key, self.me["id"], sender, counter)):
            self.out = None  # delivered: stop resending
            for s in self.sent:
                if s["to"] == sender and s.get("counter") == counter:
                    s["delivered"] = True
            self.changed = True

    def schedule(self, now):
        if self.out and now >= self.out[1]:
            self.out = None
        for k in [k for k, v in self.partial.items() if now - v["t"] > 2 * TEXT_SECONDS]:
            del self.partial[k]
        self.receipts = {k: v for k, v in self.receipts.items() if now < v[1]}
        extra = (list(self.out[0]) if self.out else []) + [v[0] for v in self.receipts.values()]
        return schedule(card_packets(self.me), extra)

    def around(self, now):
        """People heard in the last LOST_AFTER seconds, strongest signal first."""
        out = []
        for cid, h in self.heard.items():
            if cid in self.met and now - h["last"] <= LOST_AFTER:
                out.append(dict(self._public(cid), rssi=sum(h["rssi"]) // len(h["rssi"])))
        return sorted(out, key=lambda p: -p["rssi"])

    def _public(self, cid):
        """A met person as the app sees it, with the safety code once their key is known."""
        r = self.met[cid]
        out = {k: v for k, v in r.items() if k not in ("pubparts", "rx")}
        out.update(id=cid, impostor=bool(r.get("impostor")), can_text=bool(r.get("pub")) and not r.get("impostor"))
        if r.get("pub"):
            out["code"] = safety_code(self.me["pub"], r["pub"])
        return out

    # --- app side ---

    def command(self, req, now):
        cmd = req.get("cmd")
        if cmd == "state":
            met = sorted((self._public(k) for k in self.met), key=lambda r: -r["last"])
            me = {k: v for k, v in self.me.items() if k != "key"}  # the private key never leaves the service
            return {"me": me, "around": self.around(now), "met": met,
                    "waves": self.waves, "sent": self.sent, "sending": self.out is not None}
        if cmd == "set_card":
            return self._set_card(req)
        if cmd == "text":
            return self._text(str(req.get("to", "")), clean(str(req.get("text", "")), TEXT_MAX), now)
        if cmd == "waves_read":  # the app opened the Texts tab: everything up to now is read
            self.me["waves_read"] = max([w["time"] for w in self.waves], default=0)
            self.changed = True
            return {"ok": True}
        if cmd == "background":
            self.me["background"] = bool(req.get("on"))
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

    def _text(self, to, text, now):
        rec = self.met.get(to)
        if self.me["listen_only"]:
            return {"error": "listen-only is on, so nothing is sent"}
        if rec is None:
            return {"error": "unknown card id"}
        if rec.get("impostor"):
            return {"error": f"someone is copying {rec['nick']}'s card, so texting isn't safe"}
        if not rec.get("pub"):
            return {"error": f"{rec['nick']}'s key hasn't arrived yet: stay close a few seconds"}
        if not text.strip():
            return {"error": "type something first"}
        try:
            key = pair_key(self.me["key"], self.me["pub"], rec["pub"])
        except ValueError:
            return {"error": f"{rec['nick']}'s key is invalid"}
        if self.me.get("tx", 0) + 1 >= 1 << 24:
            return {"error": "text counter used up: reset your card"}  # never wrap: a nonce must not repeat
        self.me["tx"] = self.me.get("tx", 0) + 1
        self.out = (text_packets(self.me, to, self.me["tx"], text, key), now + TEXT_SECONDS, to, self.me["tx"])
        self.sent = (self.sent + [{"to": to, "nick": rec["nick"], "text": text, "time": time.time(),
                                   "counter": self.me["tx"], "delivered": False}])[-INBOX_MAX:]
        self.changed = self.urgent = True
        return {"ok": True}

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
        return {"ok": True, "me": {k: v for k, v in self.me.items() if k != "key"}}


# ---------- files ----------

def data_dir():
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "nearby")


SYSTEM_SOCKET = "/run/nearby.sock"  # nearbyd.socket: systemd starts the service when the app connects


def socket_path():
    """Where a service started by hand (not by systemd) listens."""
    run = os.environ.get("XDG_RUNTIME_DIR")
    return os.path.join(run, "nearby.sock") if run else f"/tmp/nearby-{os.getuid()}.sock"


def client_path():
    """Where the app and command line connect: a hand-started service if there is one, else systemd's."""
    if os.environ.get("NEARBY_SOCKET"):
        return os.environ["NEARBY_SOCKET"]
    return socket_path() if os.path.exists(socket_path()) else SYSTEM_SOCKET


def systemd_socket():
    """The listening socket systemd handed over (socket activation), or None."""
    if os.environ.get("LISTEN_PID") == str(os.getpid()) and int(os.environ.get("LISTEN_FDS", "0")) >= 1:
        return socket.socket(fileno=3)  # SD_LISTEN_FDS_START
    return None


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def save_json(path, value):
    tmp = path + ".tmp"
    # 0600: profile.json holds the private key. fsync: the text counter must survive a power cut.
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as f:
        json.dump(value, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)  # atomic: a power cut never leaves half a file


def load_node(folder):
    os.makedirs(folder, mode=0o700, exist_ok=True)
    for name in os.listdir(folder):  # files from 1.1 were 0644: make everything owner-only
        os.chmod(os.path.join(folder, name), 0o600)
    me = load_json(os.path.join(folder, "profile.json"), None)
    if me is None:
        me = new_profile()
        save_json(os.path.join(folder, "profile.json"), me)
    elif "key" not in me:  # a 1.1 card: add a key pair, keep everything else
        me["key"], me["pub"] = new_keypair()
        me["tx"] = 0
        save_json(os.path.join(folder, "profile.json"), me)
    return Node(me, load_json(os.path.join(folder, "met.json"), {}),
                load_json(os.path.join(folder, "waves.json"), []),
                load_json(os.path.join(folder, "sent.json"), []))


def save_node(folder, node):
    for name, value in (("profile", node.me), ("met", node.met), ("waves", node.waves), ("sent", node.sent)):
        save_json(os.path.join(folder, name + ".json"), value)
    node.changed = node.urgent = False


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
    handed = systemd_socket()
    server = handed or listen(socket_path())
    sound = None
    if not quiet:
        fd, sound = tempfile.mkstemp(suffix=".wav")
        os.close(fd)
        make_beep(sound)
        os.chmod(sound, 0o644)  # readable by the sudo user who plays it
    rotate_at = slot_at = save_at = reassert_at = 0.0
    heard_at = asked_at = time.monotonic()
    advertising = None
    slot = 0
    print(f"nearbyd: card {node.me['id']} ({node.me['nick']}), "
          f"socket {SYSTEM_SOCKET if handed else socket_path()}", flush=True)
    try:
        while True:
            now = time.monotonic()
            if not node.me.get("background", True) and now - asked_at > IDLE_EXIT:
                print("nearbyd: background is off and the app is closed, stopping", flush=True)
                return
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
                asked_at = now
            if node.urgent or (node.changed and now >= save_at):
                # urgent: a text's counter is saved before any of its fragments go on air
                save_node(folder, node)
                save_at = now + 5  # otherwise at most every 5 s: spares the SD card
    finally:
        radio.stop()
        save_node(folder, node)
        if handed:
            handed.detach()  # systemd owns it and keeps listening for the next app start
        else:
            server.close()
            os.unlink(socket_path())
        if sound:
            os.remove(sound)


# ---------- command line ----------

def ask(req, path=None):
    """Send one request to the running service and return its reply."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(10)  # the first request may wait while systemd starts the service
        s.connect(path or client_path())
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
          + ("  [listen-only]" if me["listen_only"] else "")
          + ("" if me.get("background", True) else "  [background off]"))
    print(f"Around now: {len(state['around'])}")
    for p in state["around"]:
        print(f"  {p['nick']:<10} {p['rssi']:>4} dBm  \"{p['status']}\"")
    print(f"Met: {len(state['met'])}")
    for p in state["met"]:
        key = "IMPOSTOR?" if p["impostor"] else f"code {p['code']}" if p.get("code") else "no key yet"
        print(f"  {p['nick']:<10} x{p['count']:<3} last {ago(wall - p['last'])}  card {p['id']}  {key}")
    print(f"Texts in: {len(state['waves'])}")
    for w in state["waves"][-5:]:
        print(f"  from {w['nick']}: \"{w['text']}\" ({ago(wall - w['time'])})")
    for w in state["sent"][-3:]:
        print(f"  to {w['nick']}: \"{w['text']}\" ({ago(wall - w['time'])}, "
              + ("delivered)" if w.get("delivered") else "not delivered yet)"))


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
    run.add_argument("--quiet", action="store_true", help="no beep for texts")
    sub.add_parser("status", help="show your card, who is around, who you met, texts")
    card = sub.add_parser("card", help="change your card")
    card.add_argument("--nick")
    card.add_argument("--colour", type=int)
    card.add_argument("--status")
    tx = sub.add_parser("text", help="send an encrypted text to someone you have met")
    tx.add_argument("nick")
    tx.add_argument("text")
    lo = sub.add_parser("listen", help="listen-only on/off (on = send nothing)")
    lo.add_argument("on", choices=["on", "off"])
    bg = sub.add_parser("background", help="background on/off (off = only run while the app is open)")
    bg.add_argument("on", choices=["on", "off"])
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
        elif args.cmd == "text":
            met = ask({"cmd": "state"})["met"]
            match = [p["id"] for p in met if p["nick"].lower() == args.nick.lower() or p["id"] == args.nick]
            if len(match) != 1:
                sys.exit(f"No single person called {args.nick!r} in your Met list.")
            reply = ask({"cmd": "text", "to": match[0], "text": args.text})
        elif args.cmd == "background":
            reply = ask({"cmd": "background", "on": args.on == "on"})
        else:
            reply = ask({"cmd": "listen_only", "on": args.on == "on"})
    except (FileNotFoundError, ConnectionRefusedError):
        sys.exit("nearbyd isn't running.")
    sys.exit(reply["error"] if "error" in reply else 0)


if __name__ == "__main__":
    main()
