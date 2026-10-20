#!/usr/bin/env bash
# Builds dcore-msvc-hangover:2015u3 — the VS2015 U3 MSVC toolset running natively on arm64.
#
#   ./build.sh
#
# Needs docker and the existing dcore-msvc-wine:2015u3 image: its /opt/msvc tree is a set of
# architecture-independent PE files and is reused verbatim. The Hangover release archive is
# downloaded once and cached next to this script. Everything else runs in docker; the image
# self-tests the banner and two real compiles (including <cstdint>/<windows.h>).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VERSION=11.16
TAR="$HERE/hangover_${VERSION}_ubuntu2404_noble_arm64.tar"
URL="https://github.com/AndreRH/hangover/releases/download/hangover-${VERSION}/hangover_${VERSION}_ubuntu2404_noble_arm64.tar"
STAGING="$HERE/staging"
IMAGE="dcore-msvc-hangover:2015u3"

command -v docker >/dev/null || { echo "error: docker is not on PATH" >&2; exit 1; }
docker image inspect dcore-msvc-wine:2015u3 >/dev/null 2>&1 || {
        echo "error: build/import dcore-msvc-wine:2015u3 first (see ../msvc-wine/build.sh)" >&2
        exit 1
}

[ -f "$TAR" ] || curl -L --fail -o "$TAR" "$URL"

echo "==> staging Hangover $VERSION (debs + the MSVC tree from dcore-msvc-wine)"
rm -rf "$STAGING"
mkdir -p "$STAGING/debs" "$STAGING"
tar xf "$TAR" -C "$STAGING/debs"
rm -f "$STAGING/debs"/dxvk*.tar.gz  # not needed for a console compiler image
docker create --name dcore-msvc-src dcore-msvc-wine:2015u3 /bin/true >/dev/null
trap 'docker rm -f dcore-msvc-src >/dev/null 2>&1 || true' EXIT
docker cp dcore-msvc-src:/opt/msvc "$STAGING/msvc"
cp "$HERE/../msvc-wine/cl" "$STAGING/cl"

echo "==> docker build --platform linux/arm64 -t $IMAGE"
docker build --platform linux/arm64 -t "$IMAGE" -f "$HERE/Dockerfile" "$STAGING"
echo "built $IMAGE — set compiler.image to it and compiler.platform to linux/arm64"
