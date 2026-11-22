import time
import unittest

from PIL import Image, ImageDraw

import nearby as ui

WALL = 1_000_000.0


def person(nick, colour=0, status="", rssi=-60, count=1, last=0, avatar="00" * 32):
    return {"id": nick, "nick": nick, "colour": colour, "status": status, "avatar": avatar,
            "rssi": rssi, "count": count, "last": WALL - last, "rev": 0, "first": 0}


def state(around=(), met=(), listen_only=False):
    return {"me": {"listen_only": listen_only}, "around": list(around), "met": list(met), "waves": []}


class Pieces(unittest.TestCase):
    def test_avatar_bit_layout(self):
        bits = bytearray(32)
        bits[0] = 0x80   # row 0, leftmost pixel
        bits[31] = 0x01  # row 15, rightmost pixel
        img = ui.avatar(bits.hex(), 1, "x", size=16)
        self.assertEqual(img.getpixel((0, 0)), ui.PALETTE[1])
        self.assertEqual(img.getpixel((15, 15)), ui.PALETTE[1])
        self.assertEqual(img.getpixel((1, 0)), ui.PANEL)

    def test_blank_avatar_uses_card_colour(self):
        img = ui.avatar("00" * 32, 2, "kai")
        self.assertEqual(img.size, (28, 28))
        self.assertEqual(img.getpixel((1, 1)), ui.PALETTE[2])

    def test_signal_bars(self):
        self.assertEqual([ui.signal_bars(r) for r in (-40, -55, -56, -70, -71, -85, -86, -100)],
                         [4, 4, 3, 3, 2, 2, 1, 1])

    def test_fit_cuts_with_ellipsis(self):
        d = ImageDraw.Draw(Image.new("RGB", (1, 1)))
        self.assertEqual(ui.fit(d, "hi", ui.REG, 200), "hi")
        cut = ui.fit(d, "x" * 80, ui.REG, 60)
        self.assertTrue(cut.endswith("…"))
        self.assertLessEqual(d.textlength(cut, font=ui.REG), 60)

    def test_short_ago(self):
        self.assertEqual([ui.short_ago(s) for s in (5, 61, 7200, 90000)], ["now", "1m ago", "2h ago", "1d ago"])


class Screens(unittest.TestCase):
    def test_every_screen_draws_at_full_size(self):
        people = [person(f"p{i}", i % 8, "s" * 40, rssi=-50 - 5 * i, count=i + 1, last=60 * i) for i in range(9)]
        for view in ("around", "met"):
            for st in (state(people, people), state(), state(listen_only=True), None):
                for sel in (0, 4, 8):
                    self.assertEqual(ui.render(view, st, sel, WALL).size, (ui.W, ui.H))

    def test_selected_row_is_highlighted_and_scrolled_into_view(self):
        people = [person(f"p{i}") for i in range(9)]
        img = ui.render("around", state(people), 8, WALL)
        last_row = ui.TOP + 1 + (ui.ROWS - 1) * ui.ROW
        self.assertEqual(img.getpixel((1, last_row + 5)), ui.ACCENT)  # highlight bar on the last visible row


class Keys(unittest.TestCase):
    def test_key_presses_from_raw_events(self):
        ev = ui.EVENT
        buf = (ev.pack(0, 0, 1, ui.KEY_DOWN, 1) + ev.pack(0, 0, 0, 0, 0)     # press + sync
               + ev.pack(0, 0, 1, ui.KEY_DOWN, 0)                              # release: ignored
               + ev.pack(0, 0, 1, ui.KEY_UP, 2) + ev.pack(0, 0, 4, 4, 30))     # auto-repeat + scan code
        self.assertEqual(ui.key_presses(buf), [ui.KEY_DOWN, ui.KEY_UP])
        self.assertEqual(ui.key_presses(buf[:10]), [])  # half an event

    def test_handle(self):
        self.assertEqual(ui.handle(ui.KEY_DOWN, "around", 0, 3), ("around", 1, False))
        self.assertEqual(ui.handle(ui.KEY_DOWN, "around", 2, 3), ("around", 2, False))
        self.assertEqual(ui.handle(ui.KEY_UP, "around", 0, 3), ("around", 0, False))
        self.assertEqual(ui.handle(ui.KEY_DOWN, "met", 0, 0), ("met", 0, False))
        self.assertEqual(ui.handle(ui.KEY_2, "around", 2, 3), ("met", 0, False))
        self.assertEqual(ui.handle(ui.KEY_1, "met", 2, 3), ("around", 0, False))
        self.assertTrue(ui.handle(ui.KEY_ESC, "met", 0, 0)[2])
        self.assertTrue(ui.handle(ui.KEY_Q, "met", 0, 0)[2])


class Pixels(unittest.TestCase):
    def test_rgb565(self):
        img = Image.new("RGB", (4, 1))
        img.putdata([(255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 255)])
        self.assertEqual(ui.rgb565(img), bytes.fromhex("00f8" "e007" "1f00" "ffff"))


if __name__ == "__main__":
    unittest.main()
