# syntax=docker/dockerfile:1
# dcore-msvc-hangover:2015u3 — the same byte-exact VS2015 U3 driver, natively arm64.
#
# Hangover = Wine 11.16 with ARM64EC + FEX (a JIT translating x86-64 Windows code to ARM64).
# The image is arm64: Docker does NOT emulate the container, so no Rosetta and no qemu-user.
# The MSVC tree is architecture-independent PE files taken from dcore-msvc-wine (build.sh).
# Built with --platform linux/arm64.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
# The debs are bind-mounted, not COPYed: a layer holding them would add ~300MB for nothing.
RUN --mount=type=bind,source=debs,target=/tmp/hangover \
    apt-get update \
    && apt-get install -y --no-install-recommends /tmp/hangover/*.deb ca-certificates \
    && ln -s /usr/bin/wine /usr/local/bin/wine64 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

ENV WINEPREFIX=/wine \
    WINEDEBUG=-all \
    WINEDLLOVERRIDES=mscoree,mshtml= \
    HOME=/root

COPY msvc /opt/msvc
COPY cl /usr/local/bin/cl

# Prefix creation and every self-test in ONE layer: each wineboot/cl run rewrites parts of the
# 2.5GB prefix, and separate layers would each carry a full duplicate of the changed files
# (the first build was 13.6GB this way). The final layer is the prefix as it really is.
RUN chmod +x /usr/local/bin/cl \
    && mkdir -p /work /tmp /wine \
    && { wineboot -i >/tmp/wineboot.log 2>&1 || { tail -40 /tmp/wineboot.log; exit 1; }; } \
    && cl 2>&1 | sed -n '1,3p' \
    && printf 'int dcore_probe(int a) { return a * 3 + 1; }\n' > /work/probe.c \
    && printf '#include <cstdint>\n#include <windows.h>\nunsigned long dcore_probe2(HANDLE h, std::uint32_t n) { (void)h; return (unsigned long)n + GetTickCount(); }\n' > /work/probe2.cpp \
    && cl /nologo /O2 /c /Fo/work/probe.obj /work/probe.c \
    && cl /nologo /O2 /c /Fo/work/probe2.obj /work/probe2.cpp \
    && ls -l /work/probe.obj /work/probe2.obj \
    && rm -rf /work /tmp/wineboot.log
