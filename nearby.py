#!/usr/bin/env python3
"""nearby: the Nearby app for the CardputerZero's 320x170 screen.

Shows who is around right now and everyone you have met, from the cards the
nearbyd service collects. Draws with Pillow straight to the framebuffer and
reads the built-in keyboard directly.

Keys: 1 Around, 2 Met, up/down to move, Esc or q to quit.
`nearby --snapshot out.png` draws one frame to a PNG instead.
"""
import argparse
import os
import select
import signal
import struct
import sys
import time

from PIL import Image, ImageDraw, ImageFont

import nearbyd

W, H = 320, 170
TOP, BOTTOM, ROW = 22, 15, 33
ROWS = (H - TOP - BOTTOM) // ROW  # 4 rows fit

BG, PANEL, LINE = (20, 22, 26), (34, 37, 44), (52, 56, 64)
TEXT, DIM, ACCENT = (232, 234, 237), (140, 146, 156), (255, 122, 26)
# Card colours 0-7, in the order the Me screen offers them.
PALETTE = [(255, 122, 26), (64, 196, 255), (80, 220, 120), (255, 94, 160),
           (255, 214, 10), (170, 120, 255), (255, 80, 70), (90, 140, 255)]

FONT_DIRS = [os.environ.get("NEARBY_FONT_DIR", ""), "/usr/share/fonts/truetype/dejavu"]


def font(name, size):
    for d in FONT_DIRS:
        path = os.path.join(d, name)
        if d and os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()  # shortcut: plain bitmap font if DejaVu is missing


BOLD, REG, SMALL = font("DejaVuSans-Bold.ttf", 13), font("DejaVuSans.ttf", 11), font("DejaVuSans.ttf", 10)

# evdev key codes from linux/input-event-codes.h
KEY_ESC, KEY_1, KEY_2, KEY_Q = 1, 2, 3, 16
KEY_UP, KEY_DOWN = 103, 108
KEYBOARD = "/dev/input/cardputer-zero-internal"


# ---------- drawing pieces ----------

def avatar(hexbits, colour, nick, size=28):
    """16x16 1-bit picture (2 bytes a row, leftmost pixel in the top bit) in the card's colour.
    A blank avatar shows the nickname's first letter instead."""
    colour = PALETTE[colour % len(PALETTE)]
    bits = bytes.fromhex(hexbits)
    if not any(bits):
        img = Image.new("RGB", (size, size), colour)
        ImageDraw.Draw(img).text((size / 2, size / 2), (nick[:1] or "?").upper(),
                                 font=BOLD, fill=BG, anchor="mm")
        return img
    img = Image.new("RGB", (16, 16), PANEL)
    px = img.load()
    for y in range(16):
        row = bits[2 * y] << 8 | bits[2 * y + 1]
        for x in range(16):
            if row >> (15 - x) & 1:
                px[x, y] = colour
    return img.resize((size, size), Image.NEAREST)


def signal_bars(rssi):
    """1-4 bars, same bands the old version used: right here, close, nearby, far."""
    return 4 if rssi >= -55 else 3 if rssi >= -70 else 2 if rssi >= -85 else 1


def fit(draw, text, fnt, width):
    """Cut text with an ellipsis so it fits the given pixel width."""
    if draw.textlength(text, font=fnt) <= width:
        return text
    while text and draw.textlength(text + "…", font=fnt) > width:
        text = text[:-1]
    return text + "…"


def short_ago(seconds):
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= n:
            return f"{int(seconds // n)}{unit} ago"
    return "now"


def radar(d, cx, cy, colour):
    d.ellipse([cx - 4, cy - 4, cx + 4, cy + 4], fill=colour)
    for r in (12, 20, 28):
        d.arc([cx - r, cy - r, cx + r, cy + r], -50, 50, fill=colour, width=3)
        d.arc([cx - r, cy - r, cx + r, cy + r], 130, 230, fill=colour, width=3)


def message(d, title, lines, icon=True):
    y = TOP + 18
    if icon:
        radar(d, W // 2, y + 18, LINE)
        y += 46
    d.text((W // 2, y), title, font=BOLD, fill=TEXT, anchor="mm")
    for i, line in enumerate(lines):
        d.text((W // 2, y + 18 + 14 * i), line, font=SMALL, fill=DIM, anchor="mm")


# ---------- whole screens ----------

def render(view, state, sel, wall):
    """One frame. view is "around" or "met"; state is the service's reply, or None if it's down."""
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # top bar: name and the two tabs
    d.rectangle([0, 0, W, TOP - 1], fill=PANEL)
    d.text((8, TOP // 2), "Nearby", font=BOLD, fill=ACCENT, anchor="lm")
    tabs = [("around", f"1 Around {len(state['around'])}" if state else "1 Around"),
            ("met", f"2 Met {len(state['met'])}" if state else "2 Met")]
    x = W - 6
    for key, label in reversed(tabs):
        tw = d.textlength(label, font=REG)
        x -= tw
        d.text((x, TOP // 2), label, font=REG, fill=TEXT if key == view else DIM, anchor="lm")
        if key == view:
            d.rectangle([x, TOP - 3, x + tw, TOP - 1], fill=ACCENT)
        x -= 12

    # bottom bar: keys, and listen-only when it's on
    d.line([0, H - BOTTOM, W, H - BOTTOM], fill=LINE)
    d.text((6, H - BOTTOM / 2), "↑↓ move   1/2 tabs   Esc quit", font=SMALL, fill=DIM, anchor="lm")
    if state and state["me"]["listen_only"]:
        d.text((W - 6, H - BOTTOM / 2), "LISTEN-ONLY", font=SMALL, fill=ACCENT, anchor="rm")

    if state is None:
        message(d, "Nearby service isn't running", ["Start it with:", "sudo systemctl start nearbyd"], icon=False)
        return img

    people = state[view]
    if not people:
        if view == "around":
            hint = ["You're in listen-only mode: others can't see you."] if state["me"]["listen_only"] \
                else ["Cards swap by themselves when someone", "running Nearby comes close."]
            message(d, "No one around right now", hint)
        else:
            message(d, "No one met yet", ["Keep Nearby on in your pocket.", "People you pass show up here."])
        return img

    first = min(max(0, sel - ROWS + 1), max(0, len(people) - ROWS))
    for i, p in enumerate(people[first:first + ROWS]):
        y = TOP + 1 + i * ROW
        if first + i == sel:
            d.rectangle([0, y, W, y + ROW - 2], fill=PANEL)
            d.rectangle([0, y, 2, y + ROW - 2], fill=ACCENT)
        img.paste(avatar(p["avatar"], p["colour"], p["nick"]), (8, y + 2))
        if view == "around":
            bars = signal_bars(p["rssi"])
            for b in range(4):
                h = 4 + 3 * b
                bx = W - 30 + b * 6
                d.rectangle([bx, y + 22 - h, bx + 3, y + 22], fill=PALETTE[p["colour"]] if b < bars else LINE)
            right = 40
        else:
            d.text((W - 8, y + 9), f"×{p['count']}", font=REG, fill=TEXT, anchor="rm")
            d.text((W - 8, y + 23), short_ago(wall - p["last"]), font=SMALL, fill=DIM, anchor="rm")
            right = 64
        width = W - 44 - right
        d.text((44, y + 9), fit(d, p["nick"], BOLD, width), font=BOLD, fill=TEXT, anchor="lm")
        d.text((44, y + 23), fit(d, p["status"] or "-", SMALL, width), font=SMALL, fill=DIM, anchor="lm")
    if len(people) > ROWS:  # scroll position
        top_px = TOP + (H - TOP - BOTTOM) * first // len(people)
        size = (H - TOP - BOTTOM) * ROWS // len(people)
        d.rectangle([W - 2, top_px, W - 1, top_px + size], fill=DIM)
    return img


# ---------- hardware ----------

def rgb565(img):
    """Pack an RGB image into the screen's 16-bit format (red in the top 5 bits, little-endian)."""
    import numpy as np
    a = np.asarray(img, dtype=np.uint16)
    return ((a[..., 0] >> 3) << 11 | (a[..., 1] >> 2) << 5 | a[..., 2] >> 3).astype("<u2").tobytes()


class Screen:
    def __init__(self, path="/dev/fb0"):
        self.fd = os.open(path, os.O_RDWR)
        self.last = None

    def show(self, img):
        data = rgb565(img)
        if data != self.last:  # the stride is exactly 320*2, so one write covers the screen
            os.pwrite(self.fd, data, 0)
            self.last = data


EVENT = struct.Struct("llHHi")  # struct input_event: time, type, code, value
EV_KEY = 1


def key_presses(buf):
    """Key codes pressed (or auto-repeated) in a buffer of raw input events."""
    out = []
    for off in range(0, len(buf) - EVENT.size + 1, EVENT.size):
        _, _, etype, code, value = EVENT.unpack_from(buf, off)
        if etype == EV_KEY and value in (1, 2):
            out.append(code)
    return out


def handle(code, view, sel, count):
    """Returns (view, sel, quit)."""
    if code in (KEY_ESC, KEY_Q):
        return view, sel, True
    if code == KEY_1:
        return "around", 0, False
    if code == KEY_2:
        return "met", 0, False
    if code == KEY_UP:
        return view, max(0, sel - 1), False
    if code == KEY_DOWN:
        return view, min(max(0, count - 1), sel + 1), False
    return view, sel, False


def fetch():
    try:
        return nearbyd.ask({"cmd": "state"})
    except OSError:
        return None


def run():
    screen = Screen()
    keys = os.open(KEYBOARD, os.O_RDONLY | os.O_NONBLOCK)
    view, sel, state, fetched = "around", 0, None, 0.0
    try:
        while True:
            now = time.monotonic()
            if now - fetched >= 1:
                state, fetched = fetch(), now
            count = len(state[view]) if state else 0
            sel = min(sel, max(0, count - 1))
            screen.show(render(view, state, sel, time.time()))
            if select.select([keys], [], [], 0.25)[0]:
                for code in key_presses(os.read(keys, EVENT.size * 32)):
                    view, sel, done = handle(code, view, sel, count)
                    if done:
                        return
    finally:
        os.close(keys)  # the launcher redraws itself once we exit


def main(argv=None):
    ap = argparse.ArgumentParser(description="Nearby: see who is around and who you have met.")
    ap.add_argument("--snapshot", metavar="PNG", help="draw one frame to a PNG file and exit")
    ap.add_argument("--view", choices=["around", "met"], default="around")
    args = ap.parse_args(argv)
    if args.snapshot:
        render(args.view, fetch(), 0, time.time()).save(args.snapshot)
        return
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))  # the launcher closing us: exit cleanly
    try:
        run()
    except KeyboardInterrupt:
        pass
    except OSError as e:
        sys.exit(f"nearby: can't open the screen or keyboard ({e}).")


if __name__ == "__main__":
    main()
