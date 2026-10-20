# dcore-msvc-hangover:2015u3

The VS2015 Update 3 MSVC toolset (`cl 19.00.24210`), running **natively on arm64** rather than
under Docker's `--platform linux/amd64` emulation.

It uses [Hangover](https://github.com/AndreRH/hangover) — Wine 11.16 with ARM64EC and **FEX**, a
JIT that translates x86-64 Windows code to ARM64. The container is `linux/arm64`; Docker does no
CPU emulation at all.

Why: on Apple Silicon, Rosetta crashes the wine toolchain intermittently
(`rosetta error: invalid gdt selector index 5`), and disabling Rosetta leaves qemu-user, where a
trivial compile takes **~300s**. Under Hangover/FEX a real matched ORION function compiles and judges
byte-identically in **~9.5s**, and a cold container + wineboot + probe.c takes **~9.6s**.

## Build

```sh
./build.sh
```

It downloads the Hangover `11.16` Ubuntu 24.04 arm64 release (~293MB), extracts the four debs, and
copies `/opt/msvc` out of the existing `dcore-msvc-wine:2015u3` image (the MSVC files are PE, so
they are architecture-independent). The image builds with `--platform linux/arm64` and self-tests
`cl`, `probe.c`, and `probe2.cpp` (`<cstdint>` + `<windows.h>`).

## Use

Set the project's compiler image to `dcore-msvc-hangover:2015u3` **and** its platform to
`linux/arm64` (the target is still x86-64; only the container is arm64):

```json
"compiler": { "image": "dcore-msvc-hangover:2015u3", "platform": "linux/arm64" }
```

The `POST /api/native/compiler` endpoint accepts `platform` alongside `image`/`flags`. A
`platform` of `native`/`host`/`none` omits `--platform` entirely.

The `cl` wrapper is shared with `../msvc-wine/cl`; `wine64` is a symlink to Hangover's `wine`.
