# cardputer-nearby

Beeps when another CardputerZero running this program comes close, and shows roughly how close.

Each device sends a small anonymous Bluetooth LE beacon and listens for the others. Only devices
running `nearby` can see each other. A stock Cardputer sends nothing, so it can't be spotted.

## Install

On the CardputerZero (or any Linux box with Bluetooth):

```sh
sudo curl -fsSL -o /usr/local/bin/nearby https://raw.githubusercontent.com/subnetsmith/cardputer-nearby/main/nearby.py && sudo chmod +x /usr/local/bin/nearby
```

One file, Python 3 standard library only. No pip.

To get a launcher icon on the CardputerZero, build the `.deb` instead (on any Debian-based
machine, the Cardputer included) and install it:

```sh
sh packaging/build-deb.sh && sudo dpkg -i build/nearby_*_all.deb
```

## Use

Open **Nearby** from the launcher, or from a terminal:

```sh
sudo nearby          # beep + screen
sudo nearby --quiet  # screen only
```

It needs root because it talks to the Bluetooth chip directly. Press q or Esc (or Ctrl+C) to quit;
the beacon turns off when it exits.

A CardputerZero next to a Raspberry Pi 4 running it too:

```
NEARBY  1 other Cardputer

1. right here   -44 dBm
```

## How it works

- **Talks HCI directly.** It opens a raw HCI socket and sends the LE commands itself: set a random
  address, set advertising data, start advertising, then run a passive scan. No BlueZ D-Bus, no
  libraries.
- **The beacon** is a 19-byte Service Data field with a fixed 128-bit UUID and a version byte.
  Anything else on the air is ignored.
- **Privacy.** It advertises from a non-resolvable private address that changes every 15 minutes,
  so the beacon can't be used to follow you around. `nearby` never sends the chip's real address.
- **No double beeps.** When someone's address changes, the old one goes quiet and a new one
  starts. The tracker treats a new address that starts after another went quiet as the same
  person. Beacons often go missing for a few seconds (gaps up to 4.4 s on a CardputerZero, because
  Wi-Fi and Bluetooth share one radio), so it waits 5 s before deciding. Tested with the address
  changing every 8 s for a minute: one beep, never shown as two people.
- **Sound under sudo.** Root can't reach your desktop sound server (PipeWire), so the beep plays
  as the user who ran `sudo`.
- **Distance** is the average of the last 5 signal readings: right here (above -55 dBm), close,
  nearby, far. Walls and pockets change it, so it is a rough guide.

## Tests

```sh
python3 -m unittest -v
```

They cover packet building and parsing, broken packets, the command/reply loop, address rules,
the handover logic (with the gaps measured on real hardware), the sudo beep, and the screen
fitting the 320x170 display.
