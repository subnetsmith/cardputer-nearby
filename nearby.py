#!/usr/bin/env python3
"""nearby: the Nearby app for the CardputerZero's 320x170 screen.

Four tabs over the cards the nearbyd service collects: who is Around now, who
you have Met, Waves people sent you, and Me (your own card). Draws with Pillow
straight to the framebuffer and reads the built-in keyboard directly.

`nearby --snapshot out.png [--view met]` draws one frame to a PNG instead.
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
# Card colours 0-7.
PALETTE = [(255, 122, 26), (64, 196, 255), (80, 220, 120), (255, 94, 160),
           (255, 214, 10), (170, 120, 255), (255, 80, 70), (90, 140, 255)]
COLOUR_NAMES = ["orange", "sky", "green", "pink", "yellow", "purple", "red", "blue"]

FONT_DIRS = [os.environ.get("NEARBY_FONT_DIR", ""), "/usr/share/fonts/truetype/dejavu"]


def font(name, size):
    for d in FONT_DIRS:
        path = os.path.join(d, name)
        if d and os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()  # shortcut: plain bitmap font if DejaVu is missing


BOLD, REG, SMALL = font("DejaVuSans-Bold.ttf", 13), font("DejaVuSans.ttf", 11), font("DejaVuSans.ttf", 10)
BIG = font("DejaVuSans-Bold.ttf", 16)

# ---------- keys ----------
# evdev codes from linux/input-event-codes.h
KEY_ESC, KEY_BACKSPACE, KEY_ENTER, KEY_SHIFT, KEY_SPACE = 1, 14, 28, 42, 57
KEY_1, KEY_4, KEY_Q, KEY_W, KEY_M = 2, 5, 16, 17, 50
KEY_F, KEY_X, KEY_Z, KEY_C = 33, 45, 44, 46
KEY_UP, KEY_LEFT, KEY_RIGHT, KEY_DOWN = 103, 105, 106, 108
KEYBOARD = "/dev/input/cardputer-zero-internal"
# The launcher's own arrows when not typing (cp0_keyboard_navigation_alias): F up, X down, Z left, C right.
NAV = {KEY_F: KEY_UP, KEY_X: KEY_DOWN, KEY_Z: KEY_LEFT, KEY_C: KEY_RIGHT}

# US layout: code -> (plain, shifted)
CHARS = {}
for first, row in ((2, "1!2@3#4$5%6^7&8*9(0)-_=+"), (16, "qQwWeErRtTyYuUiIoOpP[{]}"),
                   (30, "aAsSdDfFgGhHjJkKlL;:'\"`~"), (43, "\\|zZxXcCvVbBnNmM,<.>/?")):
    for i in range(0, len(row), 2):
        CHARS[first + i // 2] = row[i:i + 2]
CHARS[KEY_SPACE] = "  "


class Keyboard:
    """Turns raw key events into (code, character). Shift works held down, or tapped
    on its own just before the next key (handy on a small keyboard)."""

    def __init__(self):
        self.held = self.used = self.next_shifted = False

    def feed(self, events):
        out = []
        for code, value in events:
            if code == KEY_SHIFT:
                if value == 1:
                    self.held, self.used = True, False
                elif value == 0:
                    self.held = False
                    self.next_shifted = not self.used
                continue
            if value not in (1, 2):
                continue
            shifted = self.held or self.next_shifted
            self.used, self.next_shifted = self.held, False
            pair = CHARS.get(code)
            out.append((code, pair[shifted] if pair else None))
        return out


EVENT = struct.Struct("llHHi")  # struct input_event: time, type, code, value
EV_KEY = 1


def key_events(buf):
    """(code, value) for every key event in a buffer of raw input events. value 1 press, 2 repeat, 0 release."""
    out = []
    for off in range(0, len(buf) - EVENT.size + 1, EVENT.size):
        _, _, etype, code, value = EVENT.unpack_from(buf, off)
        if etype == EV_KEY:
            out.append((code, value))
    return out


# ---------- the app's state ----------

TABS = ["around", "met", "waves", "me"]
ME_ROWS = ["nick", "colour", "status", "avatar", "listen"]


def blank_grid():
    return [[0] * 16 for _ in range(16)]


def grid_from_hex(hexbits):
    bits = bytes.fromhex(hexbits)
    return [[(bits[2 * y] << 8 | bits[2 * y + 1]) >> (15 - x) & 1 for x in range(16)] for y in range(16)]


def grid_to_hex(grid):
    out = bytearray()
    for row in grid:
        v = 0
        for px in row:
            v = v << 1 | px
        out += v.to_bytes(2, "big")
    return out.hex()


class App:
    """Everything the screen shows, and what each key does. `ask` talks to nearbyd."""

    def __init__(self, ask):
        self.ask = ask
        self.state = None
        self.view, self.sel, self.me_sel = "around", 0, 0
        self.mode = None          # None, "wave", "nick", "status" or "avatar"
        self.original = None      # what the editor started with, to spot unsaved changes
        self.confirm = False      # Esc pressed once with unsaved changes
        self.text, self.target = "", None
        self.grid, self.cur = None, [8, 8]
        self.toast = None         # (text, until)
        self.popup = None         # (wave, until)
        self.newest_wave = None

    # --- data from the service ---

    def refresh(self, now):
        try:
            self.state = self.ask({"cmd": "state"})
        except OSError:
            self.state = None
            return
        waves = self.state["waves"]
        newest = max([w["time"] for w in waves], default=0)
        if self.newest_wave is not None and newest > self.newest_wave:
            w = max(waves, key=lambda w: w["time"])
            if w["from"] not in self.state["me"]["muted"]:
                self.popup = (w, now + 6)
        self.newest_wave = newest
        if self.view == "waves" and newest > self.state["me"].get("waves_read", 0):
            self.call({"cmd": "waves_read"}, now)

    def call(self, req, now, ok=None):
        """Send a request; show the error, or `ok`, as a toast. Returns True when it worked."""
        try:
            reply = self.ask(req)
        except OSError:
            reply = {"error": "Nearby service isn't running"}
        if "error" in reply:
            self.toast = (reply["error"], now + 3)
            return False
        if ok:
            self.toast = (ok, now + 3)
        self.refresh(now)
        return True

    def items(self):
        if not self.state:
            return []
        if self.view == "waves":
            return list(reversed(self.state["waves"]))
        return self.state.get(self.view, []) if self.view != "me" else ME_ROWS

    def unread(self):
        if not self.state:
            return 0
        seen = self.state["me"].get("waves_read", 0)
        return sum(1 for w in self.state["waves"] if w["time"] > seen and w["from"] not in self.state["me"]["muted"])

    def person(self, cid):
        return next((p for p in (self.state or {}).get("met", []) if p["id"] == cid), None)

    # --- keys ---

    def key(self, code, ch, now):
        """Handle one key press. Returns False when the app should quit."""
        if self.popup:  # any key just closes the pop-up
            self.popup = None
            return True
        if self.mode in ("nick", "status", "avatar") and code == KEY_ESC:
            # Esc means "done" on the card editors: keep the change (people press Esc to finish).
            if not self.unsaved():
                self.mode = None
            else:
                self._save_card(now)
            return True
        if self.mode == "wave" and code == KEY_ESC:
            # A wave isn't sent by Esc, so with text typed it asks before throwing it away.
            if self.unsaved() and not self.confirm:
                self.confirm = True
            else:
                self.mode, self.confirm = None, False
            return True
        self.confirm = False
        if self.mode in ("wave", "nick", "status"):
            self._typing(code, ch, now)
            return True
        code = NAV.get(code, code)
        if self.mode == "avatar":
            self._drawing(code, now)
            return True
        if code in (KEY_ESC, KEY_Q):
            return False
        if KEY_1 <= code <= KEY_4:
            self.view, self.sel = TABS[code - KEY_1], 0
            if self.view == "waves":
                self.call({"cmd": "waves_read"}, now)
            return True
        if self.view == "me":
            self._me_key(code, now)
            return True
        items = self.items()
        if code == KEY_UP:
            self.sel = max(0, self.sel - 1)
        elif code == KEY_DOWN:
            self.sel = min(max(0, len(items) - 1), self.sel + 1)
        elif not items:
            pass
        elif code in (KEY_ENTER, KEY_W) and self.view in ("around", "met"):
            self.edit("wave", "", items[self.sel])
        elif code == KEY_M:
            cid = items[self.sel]["from"] if self.view == "waves" else items[self.sel]["id"]
            muted = cid in self.state["me"]["muted"]
            nick = (self.person(cid) or {"nick": "them"})["nick"]
            self.call({"cmd": "unmute" if muted else "mute", "id": cid}, now,
                      f"{nick} unmuted" if muted else f"{nick} muted: no more pop-ups or beeps")
        return True

    def edit(self, mode, value, target=None):
        """Open an editor on value (text, or avatar hex)."""
        self.mode, self.target, self.original, self.confirm = mode, target, value, False
        if mode == "avatar":
            self.grid, self.cur = grid_from_hex(value), [8, 8]
        else:
            self.text = value

    def _save_card(self, now):
        if self.mode == "avatar":
            req, ok = {"cmd": "set_card", "avatar": grid_to_hex(self.grid)}, "Avatar saved"
        else:
            req, ok = {"cmd": "set_card", self.mode: self.text}, "Card updated"
        if self.call(req, now, ok):
            self.mode = None

    def unsaved(self):
        if self.mode == "avatar":
            return grid_to_hex(self.grid) != self.original
        return self.text != self.original

    def _me_key(self, code, now):
        me = self.state["me"] if self.state else None
        if code == KEY_UP:
            self.me_sel = max(0, self.me_sel - 1)
        elif code == KEY_DOWN:
            self.me_sel = min(len(ME_ROWS) - 1, self.me_sel + 1)
        elif not me:
            return
        elif ME_ROWS[self.me_sel] == "colour" and code in (KEY_LEFT, KEY_RIGHT, KEY_ENTER):
            step = -1 if code == KEY_LEFT else 1
            self.call({"cmd": "set_card", "colour": (me["colour"] + step) % len(PALETTE)}, now)
        elif code != KEY_ENTER:
            return
        elif ME_ROWS[self.me_sel] in ("nick", "status", "avatar"):
            self.edit(ME_ROWS[self.me_sel], me[ME_ROWS[self.me_sel]])
        elif ME_ROWS[self.me_sel] == "listen":
            on = not me["listen_only"]
            self.call({"cmd": "listen_only", "on": on}, now,
                      "Listen-only on: you're hidden" if on else "Listen-only off: others can see you")

    def _typing(self, code, ch, now):
        limit = {"wave": nearbyd.WAVE_MAX, "nick": nearbyd.NICK_MAX, "status": nearbyd.STATUS_MAX}[self.mode]
        if code == KEY_BACKSPACE:
            self.text = self.text[:-1]
        elif code == KEY_ENTER:
            if self.mode == "wave":
                p = self.target
                if self.call({"cmd": "wave", "to": p["id"], "text": self.text}, now, f"Waving at {p['nick']} for 20 s"):
                    self.mode = None
            else:
                self._save_card(now)
        elif ch and len(self.text) < limit:
            self.text += ch

    def _drawing(self, code, now):
        x, y = self.cur
        moves = {KEY_LEFT: (-1, 0), KEY_RIGHT: (1, 0), KEY_UP: (0, -1), KEY_DOWN: (0, 1)}
        if code in moves:
            dx, dy = moves[code]
            self.cur = [(x + dx) % 16, (y + dy) % 16]
        elif code == KEY_SPACE:
            self.grid[y][x] ^= 1
        elif code == KEY_BACKSPACE:
            self.grid = blank_grid()
        elif code == KEY_ENTER:
            self._save_card(now)


# ---------- drawing pieces ----------

def avatar(hexbits, colour, nick, size=28):
    """16x16 1-bit picture (2 bytes a row, leftmost pixel in the top bit) in the card's colour.
    A blank avatar shows the nickname's first letter instead."""
    colour = PALETTE[colour % len(PALETTE)]
    bits = bytes.fromhex(hexbits)
    if not any(bits):
        img = Image.new("RGB", (size, size), colour)
        ImageDraw.Draw(img).text((size / 2, size / 2), (nick[:1] or "?").upper(),
                                 font=BIG if size > 40 else BOLD, fill=BG, anchor="mm")
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
    """1-4 bars: right here, close, nearby, far."""
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


def panel(d, top, bottom):
    d.rectangle([10, top, W - 11, bottom], fill=PANEL, outline=LINE)


# ---------- screens ----------

HINTS = {"around": "F/X pick  Enter wave  M mute  Esc quit",
         "met": "F/X pick  Enter wave  M mute  Esc quit",
         "waves": "F/X scroll  M mute sender  Esc quit",
         "me": "F/X pick  Enter change  Z/C colour  Esc quit"}


def render(app, wall, now=0.0):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    st = app.state
    if app.mode == "avatar":
        draw_avatar_editor(img, d, app)
        return img

    # top bar: tabs, numbered for their keys
    d.rectangle([0, 0, W, TOP - 1], fill=PANEL)
    d.ellipse([6, 7, 14, 15], fill=ACCENT)
    labels = {"around": f"1 Around {len(st['around'])}" if st else "1 Around",
              "met": f"2 Met {len(st['met'])}" if st else "2 Met",
              "waves": "3 Waves", "me": "4 Me"}
    x = 22
    for key in TABS:
        label = labels[key]
        tw = d.textlength(label, font=REG)
        d.text((x, TOP // 2), label, font=REG, fill=TEXT if key == app.view else DIM, anchor="lm")
        if key == app.view:
            d.rectangle([x, TOP - 3, x + tw, TOP - 1], fill=ACCENT)
        if key == "waves" and app.unread():
            n = str(app.unread())
            d.rounded_rectangle([x + tw + 3, 4, x + tw + 9 + 6 * len(n), TOP - 5], radius=6, fill=ACCENT)
            d.text((x + tw + 6 + 3 * len(n), TOP // 2), n, font=SMALL, fill=BG, anchor="mm")
            tw += 10 + 6 * len(n)
        x += tw + 14

    # bottom bar: a toast, or the keys for this tab
    d.line([0, H - BOTTOM, W, H - BOTTOM], fill=LINE)
    if app.toast and now < app.toast[1]:
        d.text((6, H - BOTTOM / 2), fit(d, app.toast[0], SMALL, W - 12), font=SMALL, fill=ACCENT, anchor="lm")
    else:
        d.text((6, H - BOTTOM / 2), HINTS[app.view], font=SMALL, fill=DIM, anchor="lm")
        if st and st["me"]["listen_only"] and app.view != "me":
            d.text((W - 6, H - BOTTOM / 2), "HIDDEN", font=SMALL, fill=ACCENT, anchor="rm")

    if st is None:
        message(d, "Nearby service isn't running", ["Start it with:", "sudo systemctl start nearbyd"], icon=False)
    elif app.view == "me":
        draw_me(img, d, app)
    else:
        draw_list(img, d, app, wall)

    if app.mode in ("wave", "nick", "status"):
        draw_typing(d, app)
    if app.popup and now < app.popup[1]:
        draw_popup(img, d, app)
    return img


def draw_list(img, d, app, wall):
    st, items = app.state, app.items()
    if not items:
        if app.view == "around":
            hint = ["You're hidden (listen-only): others can't see you."] if st["me"]["listen_only"] \
                else ["Cards swap by themselves when someone", "running Nearby comes close."]
            message(d, "No one around right now", hint)
        elif app.view == "met":
            message(d, "No one met yet", ["Keep Nearby on in your pocket.", "People you pass show up here."])
        else:
            message(d, "No waves yet", ["Pick someone in Around and press Enter", "to wave at them."])
        return
    sel = min(app.sel, len(items) - 1)
    first = min(max(0, sel - ROWS + 1), max(0, len(items) - ROWS))
    muted = st["me"]["muted"]
    for i, item in enumerate(items[first:first + ROWS]):
        y = TOP + 1 + i * ROW
        if first + i == sel:
            d.rectangle([0, y, W, y + ROW - 2], fill=PANEL)
            d.rectangle([0, y, 2, y + ROW - 2], fill=ACCENT)
        if app.view == "waves":
            p = app.person(item["from"]) or {"avatar": "00" * 32, "colour": 0, "nick": item["nick"]}
            name, line, cid = item["nick"], f"“{item['text']}”" if item["text"] else "waved", item["from"]
            unread = item["time"] > st["me"].get("waves_read", 0)
            d.text((W - 8, y + 16), short_ago(wall - item["time"]), font=SMALL, fill=ACCENT if unread else DIM, anchor="rm")
            right = 52
        else:
            p, name, line, cid = item, item["nick"], item["status"] or "-", item["id"]
            if app.view == "around":
                bars = signal_bars(item["rssi"])
                for b in range(4):
                    h = 4 + 3 * b
                    bx = W - 30 + b * 6
                    d.rectangle([bx, y + 22 - h, bx + 3, y + 22], fill=PALETTE[item["colour"]] if b < bars else LINE)
                right = 40
            else:
                d.text((W - 8, y + 9), f"×{item['count']}", font=REG, fill=TEXT, anchor="rm")
                d.text((W - 8, y + 23), short_ago(wall - item["last"]), font=SMALL, fill=DIM, anchor="rm")
                right = 64
        img.paste(avatar(p["avatar"], p["colour"], p["nick"]), (8, y + 2))
        width = W - 44 - right
        if cid in muted:
            name += "  (muted)"
        d.text((44, y + 9), fit(d, name, BOLD, width), font=BOLD, fill=DIM if cid in muted else TEXT, anchor="lm")
        d.text((44, y + 23), fit(d, line, SMALL, width), font=SMALL, fill=DIM, anchor="lm")
    if len(items) > ROWS:  # scroll position
        top_px = TOP + (H - TOP - BOTTOM) * first // len(items)
        size = (H - TOP - BOTTOM) * ROWS // len(items)
        d.rectangle([W - 2, top_px, W - 1, top_px + size], fill=DIM)


def draw_me(img, d, app):
    me = app.state["me"]
    # the card as others see it
    img.paste(avatar(me["avatar"], me["colour"], me["nick"], size=48), (10, TOP + 10))
    d.text((10, TOP + 70), fit(d, me["nick"], BOLD, 100), font=BOLD, fill=PALETTE[me["colour"]])
    d.text((10, TOP + 88), "card " + me["id"], font=SMALL, fill=DIM)
    d.text((10, TOP + 102), "hidden" if me["listen_only"] else "visible", font=SMALL,
           fill=ACCENT if me["listen_only"] else DIM)
    values = {"nick": ("Nickname", me["nick"]),
              "colour": ("Colour", "◀ " + COLOUR_NAMES[me["colour"]] + " ▶"),
              "status": ("Status", me["status"] or "(none)"),
              "avatar": ("Avatar", "draw…"),
              "listen": ("Listen-only", "on (hidden)" if me["listen_only"] else "off")}
    for i, key in enumerate(ME_ROWS):
        y = TOP + 4 + i * 25
        if i == app.me_sel:
            d.rectangle([118, y, W - 4, y + 22], fill=PANEL)
            d.rectangle([118, y, 120, y + 22], fill=ACCENT)
        label, value = values[key]
        d.text((126, y + 11), label, font=SMALL, fill=DIM, anchor="lm")
        if key == "colour":
            d.rectangle([196, y + 6, 206, y + 16], fill=PALETTE[me["colour"]])
            d.text((212, y + 11), value, font=REG, fill=TEXT, anchor="lm")
        else:
            d.text((196, y + 11), fit(d, value, REG, W - 204), font=REG, fill=TEXT, anchor="lm")


def draw_typing(d, app):
    limit = {"wave": nearbyd.WAVE_MAX, "nick": nearbyd.NICK_MAX, "status": nearbyd.STATUS_MAX}[app.mode]
    title = {"wave": f"Wave at {app.target['nick']}" if app.mode == "wave" else "",
             "nick": "Your nickname", "status": "Your status"}[app.mode]
    panel(d, 34, 136)
    d.text((22, 50), fit(d, title, BOLD, W - 44), font=BOLD, fill=TEXT, anchor="lm")
    d.rectangle([22, 64, W - 23, 88], fill=BG, outline=ACCENT)
    shown = app.text + "_"
    d.text((28, 76), fit(d, shown, REG, W - 60), font=REG, fill=TEXT, anchor="lm")
    d.text((W - 26, 76), f"{len(app.text)}/{limit}", font=SMALL, fill=DIM, anchor="rm")
    d.text((22, 102), "Public: anyone nearby running Nearby can read it.", font=SMALL, fill=ACCENT, anchor="lm")
    if app.confirm:
        d.text((22, 122), "Not sent! Enter sends · Esc again discards", font=SMALL, fill=ACCENT, anchor="lm")
    else:
        d.text((22, 122), "Enter send   Esc cancel" if app.mode == "wave" else "Enter or Esc saves",
               font=SMALL, fill=DIM, anchor="lm")


def draw_popup(img, d, app):
    w = app.popup[0]
    p = app.person(w["from"]) or {"avatar": "00" * 32, "colour": 0, "nick": w["nick"]}
    panel(d, 30, 140)
    d.rectangle([10, 30, W - 11, 33], fill=PALETTE[p["colour"]])
    img.paste(avatar(p["avatar"], p["colour"], p["nick"], size=48), (24, 50))
    d.text((86, 58), fit(d, f"{w['nick']} waved", BIG, W - 110), font=BIG, fill=TEXT, anchor="lm")
    d.text((86, 84), fit(d, f"“{w['text']}”" if w["text"] else "(no message)", REG, W - 110), font=REG, fill=TEXT, anchor="lm")
    d.text((W // 2, 126), "any key to close", font=SMALL, fill=DIM, anchor="mm")


def draw_avatar_editor(img, d, app):
    cell, ox, oy = 9, 8, 13
    colour = PALETTE[app.state["me"]["colour"]] if app.state else ACCENT
    d.text((ox, 6), "Draw your avatar", font=BOLD, fill=TEXT, anchor="lm")
    for y in range(16):
        for x in range(16):
            fill = colour if app.grid[y][x] else PANEL
            d.rectangle([ox + x * cell, oy + y * cell, ox + x * cell + cell - 2, oy + y * cell + cell - 2], fill=fill)
    cx, cy = app.cur
    d.rectangle([ox + cx * cell - 1, oy + cy * cell - 1, ox + cx * cell + cell - 1, oy + cy * cell + cell - 1],
                outline=TEXT, width=1)
    preview = grid_to_hex(app.grid)
    px = ox + 16 * cell + 14
    img.paste(avatar(preview, app.state["me"]["colour"] if app.state else 0, "?", size=48), (px, 14))
    img.paste(avatar(preview, app.state["me"]["colour"] if app.state else 0, "?", size=28), (px + 58, 34))
    for i, line in enumerate(["F X Z C  move", "Space  paint/erase", "Bksp  clear all", "Enter/Esc  save"]):
        d.text((px, 78 + 15 * i), line, font=SMALL, fill=DIM)


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


def run():
    screen = Screen()
    keys = os.open(KEYBOARD, os.O_RDONLY | os.O_NONBLOCK)
    app, kb, fetched = App(nearbyd.ask), Keyboard(), 0.0
    try:
        while True:
            now = time.monotonic()
            if now - fetched >= 1 and app.mode is None:  # don't move the list under the user while typing
                app.refresh(now)
                fetched = now
            screen.show(render(app, time.time(), now))
            if select.select([keys], [], [], 0.2)[0]:
                for code, ch in kb.feed(key_events(os.read(keys, EVENT.size * 32))):
                    if not app.key(code, ch, time.monotonic()):
                        return
    finally:
        os.close(keys)  # the launcher redraws itself once we exit


def main(argv=None):
    ap = argparse.ArgumentParser(description="Nearby: see who is around and who you have met.")
    ap.add_argument("--snapshot", metavar="PNG", help="draw one frame to a PNG file and exit")
    ap.add_argument("--view", choices=TABS, default="around")
    args = ap.parse_args(argv)
    if args.snapshot:
        app = App(nearbyd.ask)
        app.view = args.view
        app.refresh(0)
        render(app, time.time()).save(args.snapshot)
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
