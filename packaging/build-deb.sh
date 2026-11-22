#!/bin/sh
# Build build/nearby_<version>_all.deb. Needs dpkg-deb (Debian, Ubuntu, Raspberry Pi OS).
set -eu
cd "$(dirname "$0")/.."
VERSION=$(python3 -c 'import json; print(json.load(open("app-builder.json"))["version"])')
ROOT=$(mktemp -d)
chmod 755 "$ROOT"
trap 'rm -rf "$ROOT"' EXIT

install -Dm755 nearby.py "$ROOT/usr/bin/nearby"
install -Dm644 packaging/nearby.desktop "$ROOT/usr/share/APPLaunch/applications/nearby.desktop"
install -Dm644 packaging/nearby-launcher.png "$ROOT/usr/share/APPLaunch/share/images/nearby.png"
install -Dm644 LICENSE "$ROOT/usr/share/doc/nearby/copyright"
mkdir -p "$ROOT/DEBIAN" build
sed "s/@VERSION@/$VERSION/" packaging/control > "$ROOT/DEBIAN/control"

dpkg-deb --root-owner-group --build "$ROOT" "build/nearby_${VERSION}_all.deb"
