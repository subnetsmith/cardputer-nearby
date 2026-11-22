#!/bin/sh
# Build build/nearby_<version>_all.deb. Needs dpkg-deb (Debian, Ubuntu, Raspberry Pi OS).
set -eu
cd "$(dirname "$0")/.."
VERSION=$(python3 -c 'import json; print(json.load(open("app-builder.json"))["version"])')
ROOT=$(mktemp -d)
chmod 755 "$ROOT"
trap 'rm -rf "$ROOT"' EXIT

install -Dm644 nearby.py "$ROOT/usr/lib/nearby/nearby.py"
install -Dm644 nearbyd.py "$ROOT/usr/lib/nearby/nearbyd.py"
install -d -m755 "$ROOT/usr/bin"
for name in nearby nearbyd; do
    printf '#!/bin/sh\nexport PYTHONDONTWRITEBYTECODE=1\nexec /usr/bin/python3 /usr/lib/nearby/%s.py "$@"\n' "$name" > "$ROOT/usr/bin/$name"
    chmod 755 "$ROOT/usr/bin/$name"
done
install -Dm644 packaging/nearbyd.service "$ROOT/usr/lib/systemd/system/nearbyd.service"
install -Dm644 packaging/nearbyd.socket "$ROOT/usr/lib/systemd/system/nearbyd.socket"
install -Dm644 packaging/nearby.desktop "$ROOT/usr/share/APPLaunch/applications/nearby.desktop"
install -Dm644 packaging/nearby-launcher.png "$ROOT/usr/share/APPLaunch/share/images/nearby.png"
install -Dm644 LICENSE "$ROOT/usr/share/doc/nearby/copyright"
mkdir -p "$ROOT/DEBIAN" build
sed "s/@VERSION@/$VERSION/" packaging/control > "$ROOT/DEBIAN/control"
install -m755 packaging/postinst packaging/prerm packaging/postrm "$ROOT/DEBIAN/"

dpkg-deb --root-owner-group --build "$ROOT" "build/nearby_${VERSION}_all.deb"
