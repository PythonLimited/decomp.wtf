#!/usr/bin/env bash
# Build the two synthetic canaries with the exact first-slice toolchains.
#
# Usage:
#   tests/canary/build.sh [all|gcc|msvc]
#
# Outputs (generated, ignored by git):
#   tests/canary/build/gcc91/acme-canary
#   tests/canary/build/vs2015/acme-canary.obj          full C++14 source, object only
#   tests/canary/build/vs2015/acme-canary-min.exe      freestanding PE + PDB
#
# The MSVC image intentionally carries headers and cl, not the VC link
# libraries. The full canary therefore compiles to an object; the freestanding
# PE canary is linked with /NODEFAULTLIB so it still produces a real PE with a
# PDB for the resolver/judge. A full linked canary needs a complete VS toolset
# with its lib/ tree mounted or built into the image.
#
# Images can be overridden:
#   GCC_IMAGE=gcc:9.1.0 GCC_PLATFORM=linux/amd64
#   MSVC_IMAGE=dcore-msvc-hangover:2015u3 MSVC_PLATFORM=linux/arm64
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/build"
mkdir -p "$out/gcc91" "$out/vs2015"

target="${1:-all}"
case "$target" in
    all|gcc|msvc) ;;
    *) echo "usage: $0 [all|gcc|msvc]" >&2; exit 2 ;;
esac

GCC_IMAGE="${GCC_IMAGE:-gcc:9.1.0}"
GCC_PLATFORM="${GCC_PLATFORM:-linux/amd64}"

machine="$(uname -m)"
if [[ -z "${MSVC_IMAGE:-}" ]]; then
    if [[ "$machine" == "arm64" || "$machine" == "aarch64" ]]; then
        MSVC_IMAGE="dcore-msvc-hangover:2015u3"
        MSVC_PLATFORM="${MSVC_PLATFORM:-linux/arm64}"
    else
        MSVC_IMAGE="dcore-msvc-wine:2015u3"
        MSVC_PLATFORM="${MSVC_PLATFORM:-linux/amd64}"
    fi
fi
MSVC_PLATFORM="${MSVC_PLATFORM:-linux/amd64}"

if [[ "$target" == "all" || "$target" == "gcc" ]]; then
    echo "== GCC: $GCC_IMAGE ($GCC_PLATFORM) =="
    docker run --rm --platform "$GCC_PLATFORM" \
        -v "$here:/work" -w /work "$GCC_IMAGE" \
        g++ -std=c++14 -O2 -g -fPIC -fno-omit-frame-pointer \
        -fno-ipa-sra -fno-ipa-cp -fno-devirtualize -fno-devirtualize-speculatively \
        -o /work/build/gcc91/acme-canary /work/src/canary.cpp
    docker run --rm --platform "$GCC_PLATFORM" "$GCC_IMAGE" g++ --version | head -1
fi

if [[ "$target" == "all" || "$target" == "msvc" ]]; then
    echo "== MSVC: $MSVC_IMAGE ($MSVC_PLATFORM) =="
    msvc_platform_args=()
    if [[ -n "$MSVC_PLATFORM" ]]; then
        msvc_platform_args=(--platform "$MSVC_PLATFORM")
    fi

    # Full canary: compile only; this image has no VC lib/ tree to link against.
    docker run --rm "${msvc_platform_args[@]}" \
        -v "$here:/work" -w /work "$MSVC_IMAGE" \
        cl /nologo /O2 /EHsc /MD /Zi /std:c++14 \
        /c /Fo:/work/build/vs2015/acme-canary.obj \
        /Fd:/work/build/vs2015/acme-canary.pdb \
        /work/src/canary.cpp

    # Freestanding PE: enough for resolver/judge preflight without the CRT.
    docker run --rm "${msvc_platform_args[@]}" \
        -v "$here:/work" -w /work "$MSVC_IMAGE" \
        cl /nologo /O2 /GS- /GR- /EHs-c- /Zi \
        /c /Fo:/work/build/vs2015/canary_pe.obj \
        /Fd:/work/build/vs2015/canary_pe.pdb \
        /work/src/canary_pe.cpp
    docker run --rm "${msvc_platform_args[@]}" \
        -v "$here:/work" -w /work "$MSVC_IMAGE" \
        sh -lc 'export WINEPREFIX=/wine WINEDEBUG=-all WINEDLLOVERRIDES="mscoree,mshtml="; \
            wine64 /opt/msvc/VC/bin/amd64/link.exe /NOLOGO /NODEFAULTLIB \
            /ENTRY:main /SUBSYSTEM:CONSOLE /DEBUG /INCREMENTAL:NO \
            /PDB:Z:/work/build/vs2015/acme-canary-min.pdb \
            /OUT:Z:/work/build/vs2015/acme-canary-min.exe \
            Z:/work/build/vs2015/canary_pe.obj'

    docker run --rm "${msvc_platform_args[@]}" "$MSVC_IMAGE" cl 2>&1 | grep -m1 "Compiler Version"
fi

echo
echo "generated:"
ls -lh "$out/gcc91/acme-canary" \
    "$out/vs2015/acme-canary.obj" \
    "$out/vs2015/acme-canary-min.exe" \
    "$out/vs2015/acme-canary-min.pdb" 2>/dev/null || true
