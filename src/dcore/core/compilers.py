"""Which compiler recompiles a unit, and with what flags: detected, overridable, always explicit.

The analysis records what the binary was built with (DWARF producer strings; PDB and Rich
header for PE). Resolution picks a driver of the same family for the function's language
(`clang` vs `clang++`, `gcc` vs `g++`, `zig cc` vs `zig c++`) and the producer's flags —
unless the project config names its own, which always win:

    "compiler": {"command": "zig cc -target x86_64-linux-gnu", "flags": ["-O2", "-g"]}

`command` is a shell-style string; only the well-known cc→c++ pairs are swapped by language,
anything else is used exactly as written. A missing driver is a loud error, never a silent
fallback: compiling with the wrong compiler just makes every score a lie.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .network import NetworkError

# (C driver, C++ sibling) spellings that get swapped when the language is C++.
_CXX_PAIRS = (("gcc", "g++"), ("clang", "clang++"), ("cc", "c++"))


def rosetta_enabled() -> bool | None:
    """Docker Desktop's “Use Rosetta for x86_64/amd64 emulation” setting on macOS (None: unknown).
    Off means every x86-64 container compile runs under qemu — minutes each for a wine toolchain."""
    if sys.platform != "darwin":
        return None
    try:
        path = Path.home() / "Library" / "Group Containers" / "group.com.docker" / "settings-store.json"
        return bool(json.loads(path.read_text(encoding="utf-8")).get("UseVirtualizationFrameworkRosetta"))
    except (OSError, ValueError):
        return None


class CompilerError(NetworkError):
    """No usable compiler; shown to the user as is."""


@dataclass
class Compiler:
    command: list[str]  # driver + fixed arguments (e.g. ["zig", "cc", "-target", ...])
    flags: list[str]
    language: str
    source_name: str
    note: str = ""
    sandbox: str = "auto"  # "docker" when the compile runs in a container image
    image: str | None = None
    platform: str | None = None  # e.g. "linux/amd64": the TARGET's arch, not the host's
    style: str = "gcc"  # "gcc" | "msvc": how the driver spells -c/-I/-Fo, and how agents spell flags

    def template(self) -> list[str]:
        """The command template compile_source fills in ({src}, {obj}, {include})."""
        if self.style == "msvc":
            # cl.exe / clang-cl (and clang --driver-mode=cl): /c, /I, /Fo. /nologo keeps the
            # banner out of the logs agents read back.
            return [*self.command, "/nologo", *self.flags, "/c", "/I{include}", "/Fo{obj}", "{src}"]
        return [*self.command, *self.flags, "-c", "-I{include}", "{src}", "-o", "{obj}"]


def _style_of(command: list[str]) -> str:
    """How this driver spells its flags. cl and clang-cl are msvc-style; clang in cl driver mode too."""
    head = os.path.basename(command[0]).lower() if command else ""
    if head in ("cl", "cl.exe", "clang-cl", "clang-cl.exe") or "--driver-mode=cl" in command:
        return "msvc"
    return "gcc"


def _swap_cxx(command: list[str]) -> list[str]:
    """clang -> clang++, gcc -> g++, zig cc -> zig c++; custom drivers stay as written."""
    if len(command) >= 2 and os.path.basename(command[0]) == "zig" and command[1] == "cc":
        return [command[0], "c++", *command[2:]]
    head = os.path.basename(command[0])
    if head in ("cl", "cl.exe", "clang-cl", "clang-cl.exe") or "--driver-mode=cl" in command:
        return command  # one driver for both languages; the source's extension picks
    for c, cxx in _CXX_PAIRS:
        if head == c or head.startswith(c + "-"):  # clang-15 -> clang++-15, gcc-12 -> g++-12
            swapped = cxx + head[len(c):]
            directory = os.path.dirname(command[0])
            return [os.path.join(directory, swapped) if directory else swapped, *command[1:]]
    return command


def _find(names: list[str]) -> str | None:
    return next((n for n in names if shutil.which(n)), None)


def _triple(fmt: str, arch: str) -> str | None:
    """The clang target triple whose objects match the project's format."""
    if fmt == "elf":
        return f"{arch}-unknown-linux-gnu"
    if fmt == "pe":
        return f"{arch}-pc-windows-msvc"
    return None


def _needs_triple(fmt: str, arch: str) -> bool:
    """False when a plain host compiler already emits this project's object format."""
    host_arch = {"arm64": "aarch64", "aarch64": "aarch64", "amd64": "x86_64", "AMD64": "x86_64"}.get(
        platform.machine(), platform.machine())
    if sys.platform == "darwin":
        return True  # macOS compilers emit Mach-O, never ELF or COFF
    if sys.platform.startswith("linux"):
        return not (fmt == "elf" and arch == host_arch)
    if sys.platform == "win32":
        return not (fmt == "pe" and arch == host_arch)
    return True


def _msvc_driver(arch: str) -> tuple[list[str], str] | None:
    """A driver that speaks MSVC flags for this arch: real cl, a clang-cl build, or clang in cl
    driver mode (the last needs no MSVC installation to *compile* — the context header carries the
    declarations — while C++ also needs the MSVC STL, which msvc-wine brings)."""
    if exe := _find(["cl", "cl.exe"]):
        return [exe], "cl, MSVC-style flags — the binary's own compiler family"
    if exe := _find(["clang-cl", "clang-cl.exe"]):
        return [exe], ("clang-cl, MSVC-style flags — approximate for C++, which needs the MSVC STL "
                       "(msvc-wine brings it); the build info's cl build is still the exact target")
    if clang := shutil.which("clang"):
        triple = f"{arch}-pc-windows-msvc"
        return ([clang, f"--target={triple}", "--driver-mode=cl"],
                f"clang in MSVC driver mode for {triple} — MSVC-style flags, the binary's own family "
                f"is cl; msvc-wine with the build info's toolset is the byte-exact driver")
    return None


def _image_driver(guess: str) -> list[str]:
    """The driver to use inside a container image: the plain family binary — the image carries the
    toolchain (gcc:8.1.0 holds gcc; the msvc-wine image holds cl). `cc` when the build info is
    silent."""
    lower = (guess or "").lower()
    if "msvc" in lower or "visual c" in lower or "microsoft c" in lower:
        return ["cl"]
    if "clang" in lower:
        return ["clang"]
    if "gcc" in lower or "gnu" in lower:
        return ["gcc"]
    return ["cc"]


def _cross_driver(arch: str, cxx: bool) -> list[str] | None:
    """An installed same-family cross driver for Linux objects (the macos-cross-toolchains naming)."""
    tail = "g++" if cxx else "gcc"
    exe = _find([f"{arch}-unknown-linux-gnu-{tail}", f"{arch}-linux-gnu-{tail}", f"{arch}-pc-linux-gnu-{tail}"])
    return [exe] if exe else None


def _detect(guess: str, language: str, fmt: str = "elf", arch: str = "x86_64") -> tuple[list[str], str]:
    """(command, note) for a compiler that produces the project's object format in this language."""
    cxx = language == "c++"
    lower = (guess or "").lower()
    triple = _triple(fmt, arch)
    if triple and _needs_triple(fmt, arch):
        # this machine can't build the binary's format natively: a same-family cross driver first
        # (byte-exactness needs the family), then clang -c to the target triple (needs no sysroot)
        if fmt == "pe" and (msvc := _msvc_driver(arch)):
            return msvc
        if ("gcc" in lower or "gnu" in lower) and (cross := _cross_driver(arch, cxx)):
            return cross, f"gcc, cross-building {fmt.upper()} {arch} — from the binary's build info"
        if shutil.which("clang"):
            return (["clang", f"--target={triple}"],
                    f"clang, cross-building {fmt.upper()} {arch} — the binary was built with "
                    f"{guess or 'an unnamed compiler'}; a matching driver (cross compiler or container) "
                    f"is needed for byte-exact output — set it in the project settings")
        if fmt == "elf" and shutil.which("zig"):
            return ["zig", "c++" if cxx else "cc", "-target", f"{arch}-linux-gnu"], "zig, cross-building ELF"
        return [], f"no compiler on this machine can emit {fmt.upper()} {arch} objects (install clang)"
    if fmt == "pe" and (exe := _find(["cl", "cl.exe"])) and "clang" not in lower and "gcc" not in lower:
        return [exe], "cl, from the binary's build info"
    if "zig" in lower and shutil.which("zig"):
        return ["zig", "c++" if cxx else "cc"], "zig, from the binary's build info"
    if "clang" in lower:
        exe = _find(["clang++", "g++", "c++"] if cxx else ["clang", "gcc", "cc"])
        if exe:
            return [exe], "clang family, from the binary's build info"
    if "gcc" in lower or "gnu" in lower:
        exe = _find(["g++", "clang++", "c++"] if cxx else ["gcc", "clang", "cc"])
        if exe:
            return [exe], "gcc family, from the binary's build info"
    exe = _find(["clang++", "g++", "c++"] if cxx else ["clang", "gcc", "cc"])
    if exe:
        return [exe], ("guessed from PATH — the binary didn't say which compiler built it; "
                       "set the driver in the project's compiler settings if this is wrong")
    return [], "no C/C++ compiler on PATH"


def docker_platform(fmt: str, arch: str) -> str | None:
    """The docker platform for the project's TARGET — pulling on an arm Mac must not silently pick
    the arm64 variant of the image and emit aarch64 objects for an x86_64 binary. A Hangover image
    is the deliberate exception: it carries the x86-64 toolset natively on arm64, so a project's
    compiler.platform override wins (see image_platform)."""
    arches = {"x86_64": "linux/amd64", "amd64": "linux/amd64",
              "aarch64": "linux/arm64", "arm64": "linux/arm64"}
    if fmt == "elf":
        return arches.get(arch)
    if fmt == "pe":
        # the msvc-wine images are linux containers: the x86/x86_64 toolsets run under wine64,
        # so both target a linux/amd64 image
        arches["x86"] = "linux/amd64"
        return arches.get(arch)
    return None


_PLATFORM_PROBES = ("linux/amd64", "linux/arm64", "linux/arm/v7")


def image_platform(cfg: dict, ccfg: dict) -> str | None:
    """The platform to run the compiler image as. Defaults to the TARGET's docker platform, but a
    project may override it: Hangover images carry the x86-64 MSVC toolset *natively on arm64*
    (Wine + ARM64EC + FEX), so the image is linux/arm64 even though the target is x86_64.
    “native”/“host” means no --platform: use whatever the image/host is."""
    override = str(ccfg.get("platform") or "").strip()
    if override:
        return None if override.lower() in ("native", "host", "none") else override
    return docker_platform(str(cfg.get("format") or "elf"), str(cfg.get("arch") or "x86_64"))


def _docker(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def image_archs(image: str) -> set[str]:
    """Architectures of the locally pulled variants, keyed by image *ID* — on some containerd
    stores `docker image inspect --platform linux/amd64` resolves the amd64 variant but still
    *reports* `.Architecture` as the host's (arm64), which read as "the target isn't pulled".
    ID compare against the bare (host-variant) inspect is what actually says which variant a
    `--platform` probe resolved to: asked for a foreign platform and got the host's ID back means
    the daemon fell back — that variant isn't there."""
    bare = _docker(["image", "inspect", image, "--format", "{{.Id}}"])
    host_id = (bare.stdout or "").strip() if bare is not None and bare.returncode == 0 else ""
    host = ""
    r = _docker(["version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"])
    if r is not None and r.returncode == 0:
        host = (r.stdout or "").strip()
    # what the image *is*, straight from its config: the only truth for a single-platform local
    # build (its bare inspect IS the foreign variant, which the ID compare below would misread
    # as a host fallback)
    r = _docker(["image", "inspect", image, "--format", "{{.Architecture}}"])
    own = (r.stdout or "").strip() if r is not None and r.returncode == 0 else ""
    found: set[str] = set()
    ids: set[str] = set()
    for platform in _PLATFORM_PROBES:
        r = _docker(["image", "inspect", "--platform", platform, image, "--format", "{{.Id}}"])
        got = (r.stdout or "").strip() if r is not None and r.returncode == 0 else ""
        if not got:
            continue
        ids.add(got)
        if platform != host and host_id and got == host_id and own and platform.rsplit("/", 1)[-1] != own:
            continue  # the daemon answered with the host's variant: this one isn't pulled
        found.add(platform.rsplit("/", 1)[-1])
    host_bare = host.rsplit("/", 1)[-1]
    single_image = bool(host_id) and ids == {host_id}
    if own in ("amd64", "arm64", "arm"):
        if not found:
            found.add(own)
        elif single_image and own != host_bare:
            # every probe answered with the one image (a foreign-only local build): its config is
            # what it is — the host-platform probe resolving is not evidence of the host arch
            found.discard(host_bare)
            found.add(own)
        # otherwise the probes resolved real variants: they know better than the config, whose
        # Architecture can name the host even for a foreign variant on some containerd stores
    if not found:  # older CLI without --platform, or a single-platform local image
        r = _docker(["image", "inspect", image, "--format", "{{.Architecture}}"])
        if r is not None and r.returncode == 0:
            found = {line.strip() for line in (r.stdout or "").splitlines() if line.strip()}
    return found


def image_present(image: str, platform: str | None = None) -> bool:
    """Is the container image pulled locally *for the wanted platform*? (Docker being down reads as
    no; a wrong-arch variant reads as no for that platform.)"""
    archs = image_archs(image)
    if platform:
        return platform.rsplit("/", 1)[-1] in archs
    return bool(archs)


def suggested_image(guess: str) -> str:
    """The container image matching the binary's compiler, when we can name one (gcc 8.1.0 -> gcc:8.1.0,
    MSVC 19.00 (VS2015 U3) -> the msvc-wine image). Only a suggestion the user types/saves/pulls
    themselves — never applied on its own."""
    m = re.search(r"GNU C(?:\+\+)?\d*\s+(\d+\.\d+(?:\.\d+)?)", guess or "") or \
        re.search(r"\bgcc\s+(\d+\.\d+(?:\.\d+)?)", guess or "", re.I)
    if m:
        return f"gcc:{m.group(1)}"
    if "VS2015 U3" in (guess or ""):
        return "dcore-msvc-wine:2015u3"
    return ""


def resolve(net, slug: str, language: str = "c", unit: str | None = None,
            cu: str | None = None, fn_flags: list[str] | None = None) -> Compiler:
    """The compiler for one function of a native project: a per-function override first, then per-file
    flags (the original build's modules were not all built the same way), then the compile unit's
    producer/flags, then the project's, then detection. Detection is only a starting point — agents
    probe (`compile_and_diff flags=…`) and adopt (`set_build_flags`).

    `compiler.image` moves the compile into a container (e.g. "gcc:8.1.0"): the driver lives inside
    the image, so it is chosen by the producer's family and skipped on PATH — this is how a Mac gets
    the binary's exact GCC instead of a cross-compiling clang."""
    if language not in ("c", "c++"):
        language = "c"
    cfg = net.cfg(net._project(slug))
    ccfg = cfg.get("compiler") or {}
    unit_cfg = ((ccfg.get("units") or {}).get(unit) or {}) if unit else {}
    cu_cfg = ((ccfg.get("cu") or {}).get(cu) or {}) if cu else {}
    project_flags = ccfg.get("flags")
    if fn_flags is not None:
        flags = [str(f) for f in fn_flags]
        note = "per-function flags"
    elif unit_cfg.get("flags") is not None:
        flags = [str(f) for f in unit_cfg["flags"]]
        note = f"per-file flags for {unit.rsplit('/', 1)[-1]}"
    elif cu_cfg.get("flags") is not None:
        flags = [str(f) for f in cu_cfg["flags"]]
        note = f"per-compile-unit flags for {cu.rsplit('/', 1)[-1]}"
    elif project_flags is not None:
        flags = [str(f) for f in project_flags]
        note = "driver and flags from the project settings"
    else:
        flags = []
        note = "driver and flags from the project settings"
    image = str(unit_cfg.get("image") or cu_cfg.get("image") or ccfg.get("image") or "").strip()
    platform = image_platform(cfg, ccfg)
    compilers = (cfg.get("analysis") or {}).get("compilers") or []
    guess = (unit_cfg.get("compiler") or cu_cfg.get("compiler")
             or (compilers[0].get("compiler") if compilers else "") or ccfg.get("guess") or "")
    if (fn_flags is None and unit_cfg.get("flags") is None and cu_cfg.get("flags") is None
            and project_flags is None and compilers):
        flags = [str(f) for f in (compilers[0].get("flags") or [])]
    if ccfg.get("command"):
        command = shlex.split(str(ccfg["command"]))
    elif image:
        # inside the container: the plain family binary — the image carries the toolchain
        command = _image_driver(guess)
        note = (f"compiling in the container image {image}"
                + (f" for {platform}" if platform else "") + " (driver from the binary's build info)")
    else:
        command, note = _detect(guess, language, str(cfg.get("format") or "elf"), str(cfg.get("arch") or "x86_64"))
        if unit_cfg.get("flags") is not None:
            note = f"per-file flags for {unit.rsplit('/', 1)[-1]}"
    if fn_flags is not None:
        note = "per-function flags"
    if not command:
        raise CompilerError("no usable C/C++ compiler: set `compiler.command` and `compiler.flags` "
                            "in the project settings (e.g. \"clang++\", [\"-O2\"])")
    if language == "c++":
        swapped = _swap_cxx(command)
        if swapped != command:
            command = swapped
            note += "; C++ driver"
    if image:
        if not shutil.which("docker"):
            raise CompilerError(f"this project compiles in {image!r}, but docker isn't on PATH — "
                                f"install/start Docker, or clear the image in the compiler settings")
        if not image_present(image, platform):
            have = ", ".join(sorted(archs)) if (archs := image_archs(image)) else "nothing"
            wanted = f" for {platform}" if platform else ""
            raise CompilerError(f"docker image {image!r} isn't pulled{wanted} (locally: {have}) — press "
                                f"“Pull the image” in the compiler card to fetch the target's architecture")
    elif not shutil.which(command[0]):
        raise CompilerError(f"{command[0]} isn't on PATH (or isn't executable): point `compiler.command` "
                            f"at your compiler in the project settings")
    if image and platform and platform.endswith("amd64") and rosetta_enabled() is False:
        note += (" · Rosetta emulation is off in Docker Desktop: this x86-64 image runs under qemu — compiles "
                 "are slow (minutes) but stable; the timeout is 8 minutes")
    return Compiler(command=command, flags=flags, language=language,
                    source_name="func.cpp" if language == "c++" else "func.c", note=note,
                    sandbox="docker" if image else "auto", image=image or None,
                    platform=platform if image else None, style=_style_of(command))


def guess_language(text: str) -> str:
    """C or C++ for a header whose language has to be guessed (a header-only regression check).

    Plain C headers are common, so default to C — but a `#include <cstdint>`, `extern "C"`, `std::`
    or a real C++ declaration must select C++. Validating a C++ header as C (`func.c`) dies at the
    first C++ include and hides the actual bad declaration from every edit gate.
    """
    text = text or ""
    cxx = re.search(
        r'extern\s*"C"'
        r"|#\s*include\s*<c(?:std|string|cstdio|cstdlib|cmath|cassert|cctype|cerrno|climits|cfloat|"
        r"cstdarg|ctime|cwchar|cuchar|stddef|stdint)[a-z]*>"
        r"|#\s*include\s*<(?:vector|string|map|unordered_map|memory|algorithm|utility|type_traits|"
        r"initializer_list|optional|variant|filesystem|thread|mutex|atomic|chrono|iostream|sstream|"
        r"fstream|regex|functional|array|tuple|bitset|deque|list|set|queue|stack)>"
        r"|\bstd\s*::|\bnamespace\s+[A-Za-z_]|\bclass\s+[A-Za-z_]|\btemplate\s*<"
        r"|\busing\s+[A-Za-z_]|\bconstexpr\b|\bnoexcept\b|\bnullptr\b|\boperator\s*[^\s(]"
        r"|\b(?:public|private|protected)\s*:|\b(?:virtual|override|final)\b"
        r"|(?<![:\w])[A-Za-z_]\w*::[A-Za-z_~]",
        text,
    )
    return "c++" if cxx else "c"
