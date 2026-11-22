#!/usr/bin/env python3
"""nearby: beep when another CardputerZero running this program is close by.

Each device sends a small anonymous Bluetooth LE beacon and listens for the
others. It talks to the Bluetooth chip directly over a raw HCI socket, so it
needs Linux, root and nothing else (standard library only).
"""
import argparse
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

# Marker every beacon carries (128-bit UUID, little-endian as sent on air).
SERVICE_UUID = bytes.fromhex("640a06fbd254461a80d7eb3e1ea00ebf")[::-1]
VERSION = 1
ROTATE_SECONDS = 15 * 60  # new random address this often, so nobody can track you
LOST_AFTER = 10.0         # seconds without a beacon before someone counts as gone
SETTLE = 5.0              # wait before beeping for a new address; longer than the worst gap seen (4.4 s)

HCI_COMMAND_PKT, HCI_EVENT_PKT = 0x01, 0x04
EVT_CMD_COMPLETE, EVT_CMD_STATUS, EVT_LE_META = 0x0E, 0x0F, 0x3E
LE_ADV_REPORT = 0x02
AD_SERVICE_DATA_128 = 0x21


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


# ---------- packets ----------

def command(opcode, params=b""):
    return struct.pack("<BHB", HCI_COMMAND_PKT, opcode, len(params)) + params


def hci_filter():
    """Kernel filter: only events, and only command replies + LE meta events."""
    ev = (1 << EVT_CMD_COMPLETE) | (1 << EVT_CMD_STATUS) | (1 << EVT_LE_META)
    return struct.pack("<IIIH2x", 1 << HCI_EVENT_PKT, ev & 0xFFFFFFFF, ev >> 32, 0)


def adv_data():
    """LE Set Advertising Data parameters: length byte + 31 bytes of AD structures."""
    body = SERVICE_UUID + bytes([VERSION])
    ad = bytes([len(body) + 1, AD_SERVICE_DATA_128]) + body
    return bytes([len(ad)]) + ad.ljust(31, b"\0")


def ad_structures(data):
    i = 0
    while i < len(data):
        n = data[i]
        if n == 0 or i + 1 + n > len(data):
            return
        yield data[i + 1], data[i + 2:i + 1 + n]
        i += 1 + n


def is_beacon(data):
    return any(t == AD_SERVICE_DATA_128 and v[:16] == SERVICE_UUID
               for t, v in ad_structures(data))


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


# ---------- who is around ----------

def distance_label(rssi):
    # shortcut: fixed RSSI bands; walls and pockets shift these, so it is a rough guide only.
    if rssi >= -55:
        return "right here"
    if rssi >= -70:
        return "close"
    if rssi >= -85:
        return "nearby"
    return "far"


class Tracker:
    def __init__(self):
        self.peers = {}  # address -> {"first", "last", "rssi": [...], "new": bool}

    def seen(self, addr, rssi, now):
        p = self.peers.setdefault(addr, {"first": now, "last": now, "rssi": [], "new": True})
        p["last"] = now
        p["rssi"] = (p["rssi"] + [rssi])[-5:]

    def tick(self, now):
        """Forget people who went quiet; return how many new people arrived."""
        # Off screen after LOST_AFTER, but kept SETTLE longer so a late new address can still match it.
        for addr in [a for a, p in self.peers.items() if now - p["last"] > LOST_AFTER + SETTLE]:
            del self.peers[addr]
        arrivals = 0
        for addr, p in list(self.peers.items()):
            if not p["new"] or now - p["first"] < SETTLE:
                continue
            p["new"] = False
            # Same person, fresh address: an older address went quiet before this one started
            # and has stayed quiet since. Reception drops beacons for seconds at a time (Wi-Fi
            # shares the radio), so this can't rely on tight timing.
            # shortcut: someone arriving within ~15 s of another leaving gets no beep; rare enough.
            old = max((a for a, q in self.peers.items() if a != addr and not q["new"]
                       and q["last"] <= p["first"] + 0.5 and now - q["last"] >= SETTLE),
                      key=lambda a: self.peers[a]["last"], default=None)
            if old:
                del self.peers[old]
            else:
                arrivals += 1
        return arrivals

    def present(self, now):
        """(label, average rssi) for everyone heard recently, strongest first."""
        out = [sum(p["rssi"]) // len(p["rssi"]) for p in self.peers.values()
               if not p["new"] and now - p["last"] <= LOST_AFTER]
        return [(distance_label(r), r) for r in sorted(out, reverse=True)]


def screen(people):
    """Fits the 320x170 screen's console (40 columns, 10 rows)."""
    if not people:
        return "NEARBY\n\nNo other Cardputers around.\n\nListening...  (q to quit)"
    head = f"NEARBY  {len(people)} other Cardputer{'s' if len(people) > 1 else ''}"
    rows = [f"{i}. {label:<11}{rssi:>5} dBm" for i, (label, rssi) in enumerate(people[:7], 1)]
    if len(people) > 7:
        rows.append(f"   ...and {len(people) - 7} more")
    return "\n".join([head, ""] + rows)


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
    else:
        sys.stdout.write("\a")


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

    def start(self):
        """(Re)start with a fresh random address. The chip refuses an address change mid-scan."""
        self.send(LE_SET_SCAN_ENABLE, b"\0\0", check=False)
        self.send(LE_SET_ADV_ENABLE, b"\0", check=False)
        self.send(LE_SET_RANDOM_ADDR, new_private_address())
        # 100-150 ms, non-connectable, random own address, all three channels
        self.send(LE_SET_ADV_PARAMS, struct.pack("<HHBBB6sBB", 0xA0, 0xF0, 0x03, 0x01, 0, bytes(6), 0x07, 0))
        self.send(LE_SET_ADV_DATA, adv_data())
        self.send(LE_SET_ADV_ENABLE, b"\1")
        # passive scan, 60 ms window every 60 ms, keep duplicates so RSSI stays fresh
        self.send(LE_SET_SCAN_PARAMS, struct.pack("<BHHBB", 0, 0x60, 0x60, 0, 0))
        self.send(LE_SET_SCAN_ENABLE, b"\1\0")

    def stop(self):
        for op, arg in ((LE_SET_ADV_ENABLE, b"\0"), (LE_SET_SCAN_ENABLE, b"\0\0")):
            try:
                self.send(op, arg, check=False)
            except (OSError, HciError):
                pass
        self.sock.close()


def quit_pressed(fd):
    """q or a lone Esc waiting on fd? (An arrow key also starts with Esc, so it doesn't count.)"""
    if not select.select([fd], [], [], 0)[0]:
        return False
    data = os.read(fd, 32)
    return data[:1] in (b"q", b"Q") or data == b"\x1b"


def run(dev, quiet):
    radio = Radio(dev)
    tracker = Tracker()
    sound = None
    if not quiet:
        fd, sound = tempfile.mkstemp(suffix=".wav")
        os.close(fd)
        make_beep(sound)
        os.chmod(sound, 0o644)  # readable by the sudo user who plays it
    keys = None
    if sys.stdin.isatty():  # launched from the Cardputer's terminal: read single keys, no echo
        import termios
        import tty
        keys = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin)
    rotate_at = drawn_at = 0.0
    try:
        while True:
            if keys and quit_pressed(sys.stdin.fileno()):
                raise KeyboardInterrupt
            now = time.monotonic()
            if now >= rotate_at:
                radio.start()
                rotate_at = now + ROTATE_SECONDS
            radio.sock.settimeout(0.5)
            try:
                packet = radio.sock.recv(260)
            except socket.timeout:
                packet = b""
            for addr, data, rssi in adv_reports(packet):
                if is_beacon(data):
                    tracker.seen(addr, rssi, now)
            if tracker.tick(now) and not quiet:
                beep(sound)
            if now - drawn_at >= 1:
                sys.stdout.write("\033[H\033[J" + screen(tracker.present(now)) + "\n")
                sys.stdout.flush()
                drawn_at = now
    finally:
        radio.stop()
        if keys:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, keys)
        if sound:
            os.remove(sound)


def _stop(*_):
    raise KeyboardInterrupt


def main(argv=None):
    ap = argparse.ArgumentParser(description="Beep when another Cardputer running nearby is close.")
    ap.add_argument("--hci", type=int, default=0, help="Bluetooth adapter number (default 0 = hci0)")
    ap.add_argument("--quiet", action="store_true", help="no sound, screen only")
    args = ap.parse_args(argv)
    if not sys.platform.startswith("linux"):
        sys.exit("nearby needs Linux (it talks to the Bluetooth chip directly).")
    # Stop cleanly (beacon off) on Ctrl+C, kill or service stop, even when started in the background.
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _stop)
    try:
        run(args.hci, args.quiet)
    except KeyboardInterrupt:
        print("\nStopped. Beacon off.")
    except PermissionError:
        sys.exit("Needs root to drive Bluetooth directly: sudo nearby")
    except OSError as e:
        sys.exit(f"Bluetooth problem ({e}). Is it on? Try: sudo rfkill unblock bluetooth && bluetoothctl power on")
    except HciError as e:
        sys.exit(f"The Bluetooth chip said no: {e}. Another app may be scanning; close it and retry.")


if __name__ == "__main__":
    main()
