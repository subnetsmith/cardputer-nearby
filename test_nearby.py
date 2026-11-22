import unittest

from PIL import Image, ImageDraw

import nearby as ui

WALL = 1_000_000.0


def person(nick, colour=0, status="", rssi=-60, count=1, last=0, avatar="00" * 32):
    return {"id": nick.lower(), "nick": nick, "colour": colour, "status": status, "avatar": avatar,
            "rssi": rssi, "count": count, "last": WALL - last, "rev": 0, "first": 0}


def me(**kw):
    m = {"id": "aaaaaa", "nick": "Ada", "colour": 1, "status": "hi", "avatar": "00" * 32, "rev": 0,
         "listen_only": False, "muted": [], "waves_read": 0}
    m.update(kw)
    return m


class FakeService:
    """Stands in for nearbyd: records requests and answers like it."""

    def __init__(self, around=(), met=None, waves=(), **me_kw):
        self.state = {"me": me(**me_kw), "around": list(around),
                      "met": list(around) if met is None else list(met), "waves": list(waves)}
        self.calls = []
        self.fail = None

    def __call__(self, req):
        self.calls.append(req)
        if self.fail:
            return {"error": self.fail}
        m = self.state["me"]
        if req["cmd"] == "set_card":
            m.update({k: v for k, v in req.items() if k != "cmd"})
        elif req["cmd"] == "listen_only":
            m["listen_only"] = req["on"]
        elif req["cmd"] == "mute":
            m["muted"].append(req["id"])
        elif req["cmd"] == "unmute":
            m["muted"].remove(req["id"])
        elif req["cmd"] == "waves_read":
            m["waves_read"] = max([w["time"] for w in self.state["waves"]], default=0)
        return self.state if req["cmd"] == "state" else {"ok": True}


def started(service, view="around"):
    app = ui.App(service)
    app.refresh(0)
    if view != "around":
        app.key(ui.KEY_1 + ui.TABS.index(view), None, 0)
    return app


def type_text(app, text):
    codes = {pair[0]: code for code, pair in ui.CHARS.items()}
    for c in text:
        app.key(codes[c], c, 0)


class Pieces(unittest.TestCase):
    def test_avatar_bit_layout(self):
        bits = bytearray(32)
        bits[0] = 0x80   # row 0, leftmost pixel
        bits[31] = 0x01  # row 15, rightmost pixel
        img = ui.avatar(bits.hex(), 1, "x", size=16)
        self.assertEqual(img.getpixel((0, 0)), ui.PALETTE[1])
        self.assertEqual(img.getpixel((15, 15)), ui.PALETTE[1])
        self.assertEqual(img.getpixel((1, 0)), ui.PANEL)

    def test_grid_round_trip_matches_avatar_layout(self):
        g = ui.blank_grid()
        g[0][0] = g[15][15] = g[3][7] = 1
        hexbits = ui.grid_to_hex(g)
        self.assertEqual(hexbits[:4], "8000")
        self.assertEqual(ui.grid_from_hex(hexbits), g)

    def test_signal_bars(self):
        self.assertEqual([ui.signal_bars(r) for r in (-40, -55, -56, -70, -71, -85, -86, -100)],
                         [4, 4, 3, 3, 2, 2, 1, 1])

    def test_fit_cuts_with_ellipsis(self):
        d = ImageDraw.Draw(Image.new("RGB", (1, 1)))
        self.assertEqual(ui.fit(d, "hi", ui.REG, 200), "hi")
        cut = ui.fit(d, "x" * 80, ui.REG, 60)
        self.assertTrue(cut.endswith("…"))
        self.assertLessEqual(d.textlength(cut, font=ui.REG), 60)

    def test_rgb565(self):
        img = Image.new("RGB", (4, 1))
        img.putdata([(255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 255)])
        self.assertEqual(ui.rgb565(img), bytes.fromhex("00f8" "e007" "1f00" "ffff"))


class Keys(unittest.TestCase):
    def test_key_events_from_raw(self):
        ev = ui.EVENT
        buf = ev.pack(0, 0, 1, 30, 1) + ev.pack(0, 0, 0, 0, 0) + ev.pack(0, 0, 1, 30, 0) + ev.pack(0, 0, 4, 4, 30)
        self.assertEqual(ui.key_events(buf), [(30, 1), (30, 0)])
        self.assertEqual(ui.key_events(buf[:10]), [])

    def test_us_layout(self):
        kb = ui.Keyboard()
        self.assertEqual(kb.feed([(16, 1), (2, 1), (57, 1), (52, 1), (28, 1)]),
                         [(16, "q"), (2, "1"), (57, " "), (52, "."), (28, None)])

    def test_shift_held(self):
        kb = ui.Keyboard()
        out = kb.feed([(42, 1), (30, 1), (2, 1), (42, 0), (30, 1)])
        self.assertEqual([c for _, c in out], ["A", "!", "a"])

    def test_shift_tapped_shifts_next_key_only(self):
        kb = ui.Keyboard()
        out = kb.feed([(42, 1), (42, 0), (30, 1), (30, 0), (30, 1)])
        self.assertEqual([c for _, c in out], ["A", "a"])

    def test_releases_and_repeats(self):
        kb = ui.Keyboard()
        self.assertEqual(kb.feed([(30, 1), (30, 2), (30, 0)]), [(30, "a"), (30, "a")])


class Tabs(unittest.TestCase):
    def test_number_keys_switch_tabs_and_esc_quits(self):
        app = started(FakeService())
        for i, tab in enumerate(ui.TABS):
            app.key(ui.KEY_1 + i, None, 0)
            self.assertEqual(app.view, tab)
        self.assertFalse(app.key(ui.KEY_ESC, None, 0))
        self.assertFalse(app.key(ui.KEY_Q, "q", 0))

    def test_selection_stays_in_range(self):
        app = started(FakeService(around=[person("A"), person("B")]))
        for _ in range(5):
            app.key(ui.KEY_DOWN, None, 0)
        self.assertEqual(app.sel, 1)
        for _ in range(5):
            app.key(ui.KEY_UP, None, 0)
        self.assertEqual(app.sel, 0)

    def test_launcher_letters_move_like_arrows(self):
        app = started(FakeService(around=[person("A"), person("B")]))
        app.key(ui.KEY_X, "x", 0)
        self.assertEqual(app.sel, 1)
        app.key(ui.KEY_F, "f", 0)
        self.assertEqual(app.sel, 0)

    def test_letters_still_type_when_typing(self):
        app = started(FakeService(around=[person("Mo")]))
        app.key(ui.KEY_ENTER, None, 0)
        type_text(app, "fxzc")
        self.assertEqual(app.text, "fxzc")

    def test_service_down(self):
        def down(req):
            raise ConnectionRefusedError
        app = ui.App(down)
        app.refresh(0)
        self.assertIsNone(app.state)
        self.assertTrue(app.key(ui.KEY_ENTER, None, 0))  # nothing to act on, no crash
        self.assertEqual(ui.render(app, WALL).size, (ui.W, ui.H))


class Waving(unittest.TestCase):
    def test_wave_flow(self):
        svc = FakeService(around=[person("Mo")])
        app = started(svc)
        app.key(ui.KEY_ENTER, None, 0)
        self.assertEqual(app.mode, "wave")
        type_text(app, "hi 1q")       # digits and q type while typing: no tab switch, no quit
        self.assertEqual((app.view, app.text), ("around", "hi 1q"))
        app.key(ui.KEY_BACKSPACE, None, 0)
        app.key(ui.KEY_ENTER, None, 1)
        self.assertIn({"cmd": "text", "to": "mo", "text": "hi 1"}, svc.calls)
        self.assertIsNone(app.mode)
        self.assertIn("Sending to Mo", app.toast[0])

    def test_wave_text_capped(self):
        app = started(FakeService(around=[person("Mo")]))
        app.key(ui.KEY_W, "w", 0)
        type_text(app, "a" * 50)
        self.assertEqual(len(app.text), 40)

    def test_wave_error_keeps_composer_open(self):
        svc = FakeService(around=[person("Mo")])
        app = started(svc)
        app.key(ui.KEY_ENTER, None, 0)
        svc.fail = "listen-only is on, so nothing is sent"
        app.key(ui.KEY_ENTER, None, 0)
        self.assertEqual(app.mode, "wave")
        self.assertIn("listen-only", app.toast[0])

    def test_esc_cancels_composer_without_quitting(self):
        app = started(FakeService(around=[person("Mo")]))
        app.key(ui.KEY_ENTER, None, 0)
        self.assertTrue(app.key(ui.KEY_ESC, None, 0))
        self.assertIsNone(app.mode)

    def test_mute_toggles(self):
        svc = FakeService(around=[person("Mo")])
        app = started(svc)
        app.key(ui.KEY_M, "m", 0)
        self.assertEqual(svc.state["me"]["muted"], ["mo"])
        app.key(ui.KEY_M, "m", 0)
        self.assertEqual(svc.state["me"]["muted"], [])


class Inbox(unittest.TestCase):
    def wave(self, who, t, text="hey"):
        return {"from": who, "nick": who.title(), "text": text, "time": t, "wid": 1}

    def test_popup_only_for_new_waves(self):
        svc = FakeService(met=[person("Mo")], waves=[self.wave("mo", 10)])
        app = started(svc)
        self.assertIsNone(app.popup)                   # old waves don't pop up at start
        svc.state["waves"].append(self.wave("mo", 20, "come say hi"))
        app.refresh(5)
        self.assertEqual(app.popup[0]["text"], "come say hi")
        self.assertTrue(app.key(ui.KEY_ESC, None, 6))  # Esc closes the pop-up, doesn't quit
        self.assertIsNone(app.popup)

    def test_muted_sender_no_popup_no_unread(self):
        svc = FakeService(met=[person("Mo")], muted=["mo"])
        app = started(svc)
        svc.state["waves"].append(self.wave("mo", 20))
        app.refresh(5)
        self.assertIsNone(app.popup)
        self.assertEqual(app.unread(), 0)

    def test_unread_cleared_by_opening_waves(self):
        svc = FakeService(met=[person("Mo")], waves=[self.wave("mo", 10), self.wave("mo", 20)])
        app = started(svc)
        self.assertEqual(app.unread(), 2)
        app.key(ui.KEY_1 + ui.TABS.index("waves"), None, 0)
        self.assertEqual(app.unread(), 0)
        self.assertEqual(app.items()[0]["time"], 20)  # newest first


class MeTab(unittest.TestCase):
    def go(self, svc, row):
        app = started(svc, "me")
        for _ in range(ui.ME_ROWS.index(row)):
            app.key(ui.KEY_DOWN, None, 0)
        return app

    def test_edit_nickname(self):
        svc = FakeService()
        app = self.go(svc, "nick")
        app.key(ui.KEY_ENTER, None, 0)
        self.assertEqual(app.text, "Ada")
        for _ in range(3):
            app.key(ui.KEY_BACKSPACE, None, 0)
        type_text(app, "zed")
        app.key(ui.KEY_ENTER, None, 0)
        self.assertEqual(svc.state["me"]["nick"], "zed")
        self.assertIsNone(app.mode)

    def test_colour_wraps_both_ways(self):
        svc = FakeService(colour=7)
        app = self.go(svc, "colour")
        app.key(ui.KEY_RIGHT, None, 0)
        self.assertEqual(svc.state["me"]["colour"], 0)
        app.key(ui.KEY_LEFT, None, 0)
        self.assertEqual(svc.state["me"]["colour"], 7)

    def test_listen_only_toggle(self):
        svc = FakeService()
        app = self.go(svc, "listen")
        app.key(ui.KEY_ENTER, None, 0)
        self.assertTrue(svc.state["me"]["listen_only"])
        app.key(ui.KEY_ENTER, None, 0)
        self.assertFalse(svc.state["me"]["listen_only"])

    def test_draw_and_save_avatar(self):
        svc = FakeService()
        app = self.go(svc, "avatar")
        app.key(ui.KEY_ENTER, None, 0)
        self.assertEqual((app.mode, app.cur), ("avatar", [8, 8]))
        app.key(ui.KEY_SPACE, " ", 0)                      # paint (8, 8)
        for _ in range(9):
            app.key(ui.KEY_LEFT, None, 0)                  # wraps round to x = 15
        app.key(ui.KEY_SPACE, " ", 0)
        app.key(ui.KEY_ENTER, None, 0)
        g = ui.grid_from_hex(svc.state["me"]["avatar"])
        self.assertEqual((g[8][8], g[8][15], sum(map(sum, g))), (1, 1, 2))
        self.assertIsNone(app.mode)

    def test_avatar_moves_with_letters_and_backspace_clears(self):
        svc = FakeService(avatar="ff" * 32)
        app = self.go(svc, "avatar")
        app.key(ui.KEY_ENTER, None, 0)
        app.key(ui.KEY_C, "c", 0)
        app.key(ui.KEY_F, "f", 0)
        self.assertEqual(app.cur, [9, 7])
        app.key(ui.KEY_Z, "z", 0)
        app.key(ui.KEY_X, "x", 0)
        self.assertEqual(app.cur, [8, 8])
        app.key(ui.KEY_BACKSPACE, None, 0)
        self.assertEqual(sum(map(sum, app.grid)), 0)

    def test_colour_with_z_and_c(self):
        svc = FakeService(colour=3)
        app = self.go(svc, "colour")
        app.key(ui.KEY_C, "c", 0)
        self.assertEqual(svc.state["me"]["colour"], 4)
        app.key(ui.KEY_Z, "z", 0)
        self.assertEqual(svc.state["me"]["colour"], 3)

    def test_esc_saves_the_avatar(self):
        svc = FakeService()
        app = self.go(svc, "avatar")
        app.key(ui.KEY_ENTER, None, 0)
        app.key(ui.KEY_SPACE, " ", 0)
        app.key(ui.KEY_ESC, None, 0)               # Esc = done: the drawing is kept
        self.assertIsNone(app.mode)
        self.assertEqual(ui.grid_from_hex(svc.state["me"]["avatar"])[8][8], 1)
        self.assertEqual(app.toast[0], "Avatar saved")

    def test_esc_saves_text_fields(self):
        svc = FakeService()
        app = self.go(svc, "status")
        app.key(ui.KEY_ENTER, None, 0)
        type_text(app, "x")
        app.key(ui.KEY_ESC, None, 0)
        self.assertEqual((app.mode, svc.state["me"]["status"]), (None, "hix"))

    def test_esc_with_no_changes_saves_nothing(self):
        svc = FakeService()
        app = self.go(svc, "nick")
        app.key(ui.KEY_ENTER, None, 0)
        app.key(ui.KEY_ESC, None, 0)
        self.assertIsNone(app.mode)
        self.assertFalse(any(c["cmd"] == "set_card" for c in svc.calls))

    def test_failed_save_keeps_the_editor_open(self):
        svc = FakeService()
        app = self.go(svc, "nick")
        app.key(ui.KEY_ENTER, None, 0)
        type_text(app, "x")
        svc.fail = "nickname can't be empty"
        app.key(ui.KEY_ESC, None, 0)
        self.assertEqual(app.mode, "nick")
        self.assertIn("empty", app.toast[0])


class WaveEsc(unittest.TestCase):
    def test_esc_warns_before_dropping_a_typed_wave(self):
        svc = FakeService(around=[person("Mo")])
        app = started(svc)
        app.key(ui.KEY_ENTER, None, 0)
        type_text(app, "hey")
        app.key(ui.KEY_ESC, None, 0)
        self.assertEqual((app.mode, app.confirm), ("wave", True))
        type_text(app, "x")                        # carrying on typing clears the warning
        self.assertFalse(app.confirm)
        app.key(ui.KEY_ESC, None, 0)
        app.key(ui.KEY_ESC, None, 0)
        self.assertIsNone(app.mode)
        self.assertFalse(any(c["cmd"] == "text" for c in svc.calls))


class Screens(unittest.TestCase):
    def test_every_screen_draws_at_full_size(self):
        people = [person(f"P{i}", i % 8, "s" * 40, rssi=-50 - 5 * i, count=i + 1, last=60 * i) for i in range(9)]
        waves = [{"from": "p1", "nick": "P1", "text": "w" * 18, "time": WALL - 5, "wid": 1}]
        for kw in ({}, {"listen_only": True}):
            for view in ui.TABS:
                for svc in (FakeService(around=people, waves=waves, **kw), FakeService(**kw)):
                    app = started(svc, view)
                    for sel in (0, 8):
                        app.sel = sel
                        self.assertEqual(ui.render(app, WALL).size, (ui.W, ui.H))
        app = started(FakeService(around=people), "around")
        app.key(ui.KEY_ENTER, None, 0)
        self.assertEqual(ui.render(app, WALL).size, (ui.W, ui.H))


if __name__ == "__main__":
    unittest.main()
