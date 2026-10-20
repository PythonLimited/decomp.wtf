# dcore-msvc-wine:2015u3 — the byte-exact Windows driver for VS2015 U3 binaries.
#
# cl 14.00.24215 (VS2015 Update 3) under wine, with the toolset's own headers. A
# linux/amd64 container: dcore runs it through compiler.image and passes --platform
# (see docker_platform in src/dcore/core/compilers.py). Build it with build.sh and a
# Visual Studio 2015 Update 3 Community ISO — no Microsoft server hosts those anymore.
# ubuntu:24.04 carries wine 9. 22.04's wine 6 died at wineboot under qemu-user emulation on a
# macOS 27 host (the alloc_pages_vprot assertion) — the 24.04 build's self-test below is what
# proved the fix, so the base stays here.
FROM --platform=linux/amd64 ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends wine64 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/lib/wine/wine64 /usr/local/bin/wine64

ENV WINEPREFIX=/wine \
    WINEDEBUG=-all \
    WINEDLLOVERRIDES=mscoree,mshtml=

COPY staging/VC14 /opt/msvc/VC
# The SDK header sets the product's own compiles had: the Universal CRT (crtdefs.h includes
# corecrt.h from here) and the um/shared trees windows.h lives in. Without them every real
# compile of game code dies at <cstdint> -> corecrt.h.
COPY staging/sdk /opt/msvc/sdk
COPY cl /usr/local/bin/cl
RUN chmod +x /usr/local/bin/cl

# Self-test at build time: the banner must name a 19.00 compiler (VS2015 U3 = 19.00.24210),
# and cl must compile real objects through wine - or the image is a lie. The paths are the
# /work form dcore always passes: the wrapper bridges them to Z:\work for cl. probe2 goes
# through <cstdint> and <windows.h> so a missing SDK set can never build silently again.
#
# wineboot MUST run in the same layer as the first cl use: a prefix snapshotted in its own
# layer comes out half-initialized and cl dies with D8037 (learned the hard way).
RUN wine64 wineboot -i >/dev/null 2>&1 \
    && cl 2>&1 | head -2 \
    && mkdir -p /work \
    && printf 'int dcore_probe(int a) { return a * 3 + 1; }\n' > /work/probe.c \
    && printf '#include <cstdint>\n#include <windows.h>\nunsigned long dcore_probe2(HANDLE h, std::uint32_t n) { (void)h; return (unsigned long)n + GetTickCount(); }\n' > /work/probe2.cpp \
    && cl /nologo /O2 /c /Fo/work/probe.obj /work/probe.c \
    && cl /nologo /O2 /c /Fo/work/probe2.obj /work/probe2.cpp \
    && ls -l /work/probe.obj /work/probe2.obj
