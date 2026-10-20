"""Sandboxed compilation of untrusted agent-submitted C.

Agents never get to run their own compiler for anything that counts: every score and
every match is produced here, on the coordinator, with the project's pinned toolchain.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from . import wsl

MAX_SOURCE_BYTES = 64 * 1024
# Per-compile resource caps (address space, CPU seconds, output file size) and a global
# concurrency cap, so a hostile submission can't take the host down with it.
LIMITS = ["--as=2147483648", "--cpu=30", "--fsize=67108864"]
_SLOTS = threading.BoundedSemaphore(max(2, (os.cpu_count() or 4) - 1))

_COMMENTS_AND_STRINGS = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
# the freestanding headers are pure declarations every toolchain ships, and byte-exactness can
# need them: va_start&co must be the compiler's own <cstdarg> (a hand-rolled shim drifts from the
# generated code), our own context.h already ships <cstdint>, and atomics/SIMD need the compiler's
# intrinsic declarations (<intrin.h> and the <*intrin.h> family) — hand-declaring _Interlocked*
# makes a call where the original inlined a lock op
_INCLUDE_OK = (r"\s*(?:cstdarg|stdarg\.h|cstddef|cstdint|stddef\.h|stdint\.h|[a-z0-9]*intrin\.h)\s*>")
_FORBIDDEN = [
    (re.compile(r"\b(__)?asm(__)?\b"), "inline assembly is not allowed: matches must come from C/C++"),
    (re.compile(r"\b(GLOBAL_ASM|INCLUDE_ASM|INCLUDE_RODATA|NON_MATCHING)\b"), "asm-include macros are not allowed"),
    (re.compile(r"\.incbin\b"), ".incbin is not allowed"),
    (re.compile(r"__attribute__\s*\(\(\s*(section|naked)\b"), "section/naked attributes are not allowed"),
    (re.compile(r"(#\s*pragma\s+(?!intrinsic\b)|\b_Pragma)\b"),
     "pragmas are not allowed (ask the project admin to whitelist one); #pragma intrinsic(<CRT fn>) is "
     "allowed because it changes codegen to the original builtin"),
    (re.compile(rf"#\s*include\s*<(?!{_INCLUDE_OK})"),
     "only the freestanding <cstdarg>/<cstddef>/<cstdint> and the compiler's intrinsic headers "
     "(<intrin.h>, <immintrin.h>, …) are allowed; everything else you need is in context.h"),
]
_INCLUDE = re.compile(r'#\s*include\s*"([^"]+)"')


class SourceRejected(ValueError):
    pass


def check_source(source: str) -> None:
    if len(source.encode()) > MAX_SOURCE_BYTES:
        raise SourceRejected(f"source too large (max {MAX_SOURCE_BYTES} bytes)")
    for inc in _INCLUDE.findall(source):
        if inc.startswith("/") or ".." in inc.split("/"):
            raise SourceRejected(f"include path not allowed: {inc}")
    code = _COMMENTS_AND_STRINGS.sub(" ", source)
    for pattern, why in _FORBIDDEN:
        if pattern.search(code):
            raise SourceRejected(why)


def check_header(text: str) -> None:
    """Header edits get the same fence as submissions — no pragmas, asm, incbin or attributes; a
    match must come from reconstructed C/C++, not from linker directives riding in context.h. The
    generated types block is exempt: it is ours, and every compile replaces it anyway."""
    from . import interfaces

    code = _COMMENTS_AND_STRINGS.sub(" ", interfaces.strip_types(text))
    for pattern, why in _FORBIDDEN:
        if pattern.search(code):
            raise SourceRejected(why)


@dataclass
class CompilerConfig:
    cmd: list[str]
    timeout: float = 15.0
    sandbox: str = "auto"  # auto | bwrap | docker | none
    image: str | None = None  # for sandbox = "docker"
    platform: str | None = None  # e.g. "linux/amd64": docker must pick the TARGET's variant
    ro_paths: tuple[str, ...] = ()
    include_dirs: tuple[str, ...] = ()  # absolute paths of extra (static) header dirs
    runtime32: str | None = None  # 32-bit x86 C runtime for old i386 compiler binaries (see toolchains)
    wsl: bool = False  # a Linux toolchain on Windows: runs inside WSL 2, `cmd` holds WSL paths (see wsl.py)


DOCKER_TIMEOUT = 480  # seconds; x86-64 wine under qemu needs minutes, not seconds (measured 230-330s cold)


@dataclass
class CompileResult:
    ok: bool
    obj: bytes | None
    log: str
    infra: bool = False  # the compiler never ran: the host's x86 translation / docker failed, not the code


def infra_crash(log: str) -> str | None:
    """A plain explanation when a failed run is the machine's x86 translation or container runtime,
    not the submitted code. Those crashes are intermittent; compile_source retries them."""
    text = (log or "").lower()
    if "rosetta error" in text or "invalid gdt selector" in text:
        return ("THE X86 TRANSLATION LAYER CRASHED (Rosetta: invalid gdt selector) — this is not your code; "
                "the compile was retried. Rosetta is far faster than qemu for this container, so keep “Use "
                "Rosetta for x86_64/amd64 emulation on Apple Silicon” enabled. If the crash keeps repeating, "
                "turn it off — but x86-64 compiles then run under qemu and take minutes each.")
    if "qemu: uncaught target signal" in text:
        return ("THE X86 TRANSLATION LAYER CRASHED (qemu) — this is not your code; the compile was retried. "
                "If it repeats, restart Docker Desktop or re-enable Rosetta emulation.")
    if "cannot connect to the docker daemon" in text or "is the docker daemon running" in text:
        return ("THE COMPILER CONTAINER COULD NOT START — Docker isn't running or isn't answering. This is not "
                "your code: start Docker Desktop, then retry.")
    return None


def valid_object(data: bytes | None) -> bool:
    """Whether the bytes start like a real object file (ELF, PE/COFF, Mach-O or LLVM bitcode). A
    zero-filled or truncated file means the toolchain died while emitting it — wine under a bad
    translation layer does this occasionally, and the compile still exits 0."""
    if not data or len(data) < 4:
        return False
    if data[:4] in (b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                    b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"BC\xc0\xde"):
        return True
    # COFF starts with the machine id; 0x0000 is the tell-tale of an unwritten file
    return (len(data) >= 20
            and int.from_bytes(data[:2], "little") in (0x14C, 0x8664, 0xAA64, 0x1C0, 0x1C4, 0x200))


def _sandbox_mode(cfg: CompilerConfig) -> str:
    if cfg.wsl:
        return "wsl"
    if cfg.sandbox != "auto":
        return cfg.sandbox
    return "bwrap" if shutil.which("bwrap") else "none"


def _root(cfg: CompilerConfig, work: Path) -> str:
    """How the compiler sees the work folder (in WSL it works on a copy, see wsl.run)."""
    mode = _sandbox_mode(cfg)
    return "/work" if mode in ("bwrap", "docker") else wsl.stage_dir() if mode == "wsl" else str(work)


def _wrap(cfg: CompilerConfig, work: Path, argv: list[str]) -> list[str]:
    mode = _sandbox_mode(cfg)
    if mode in ("none", "bwrap") and shutil.which("prlimit"):
        argv = ["prlimit", *LIMITS, "--", *argv]
    if mode == "none":
        return argv
    if mode == "docker":
        if not cfg.image:
            raise RuntimeError("sandbox = 'docker' needs compiler.image")
        # MSVC under wine is heavier than a plain gcc compile: cl spawns c1xx and a wineserver,
        # so the wine images get more room (same driver spellings compilers.py recognizes)
        driver = os.path.basename(argv[0]).lower() if argv else ""
        msvc = driver in ("cl", "cl.exe") or "clang-cl" in driver or "--driver-mode=cl" in argv
        caps = ["--memory", "2g", "--pids-limit", "256"] if msvc else ["--memory", "512m", "--pids-limit", "64"]
        argv_out = ["docker", "run", "--rm", "--network", "none", *caps]
        if cfg.platform:
            # without this, an arm Mac runs the arm64 variant of the image and the "object" comes
            # back aarch64 while the project is x86_64 (or the other way around)
            argv_out += ["--platform", cfg.platform]
        return [*argv_out, "-v", f"{work}:/work", "-w", "/work", cfg.image, *argv]
    if mode == "bwrap":
        # /tmp first, so read-only mounts of paths that live under /tmp are not hidden by it.
        cmd = ["bwrap", "--tmpfs", "/tmp", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib64", "/lib64",
               "--symlink", "usr/bin", "/bin", "--proc", "/proc", "--dev", "/dev"]
        if cfg.runtime32:
            # i386 binaries hardcode /lib/ld-linux.so.2; give them a private /lib with the pinned loader,
            # and point the loader at the pinned 32-bit libraries. 64-bit tools ignore those libraries.
            cmd += ["--dir", "/lib", "--ro-bind", f"{cfg.runtime32}/ld-linux.so.2", "/lib/ld-linux.so.2",
                    "--ro-bind", cfg.runtime32, "/opt/rt32", "--setenv", "LD_LIBRARY_PATH", "/opt/rt32"]
        else:
            cmd += ["--symlink", "usr/lib", "/lib"]
        for p in cfg.ro_paths:
            cmd += ["--ro-bind", p, p]
        cmd += ["--bind", str(work), "/work", "--chdir", "/work", "--unshare-all", "--die-with-parent", "--new-session"]
        return [*cmd, "--", *argv]
    raise RuntimeError(f"unknown sandbox mode {mode!r}")


def _exec(cfg: CompilerConfig, work: Path, argv: list[str], timeout: float, cwd: Path | None = None, **stage):
    """`stage`: in WSL, run on a copy in WSL's own file system (wsl.run's outputs, inputs and stage)."""
    if _sandbox_mode(cfg) == "wsl":
        return wsl.run(argv, cwd or work, timeout, **stage)
    # in the work folder, never in the app's own: KMC GCC's assembler (binutils 2.6) can't read its input when the
    # current directory is / ("Bad file descriptor"), which it is for decomp.wtf started by a service or in Docker
    return subprocess.run(_wrap(cfg, work, argv), cwd=cwd or work, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout)


def run_in(cfg: CompilerConfig, work: Path, argv: list[str], timeout: float = 300, *,
           inputs: list[str] | None = None, outputs: list[str] | None = None) -> subprocess.CompletedProcess:
    """Run a toolchain command inside `work` (the sandbox's /work), e.g. to build a whole exported project.
    Paths in `argv` must be relative to `work`. In WSL, naming the files it reads (`inputs`) and writes (`outputs`)
    lets old 32-bit compilers work on a copy in WSL's own file system, which they need (see wsl.run)."""
    return _exec(cfg, Path(work), argv, timeout, cwd=Path(work),
                 **({} if outputs is None else {"inputs": inputs, "outputs": outputs}))


def compile_source(cfg: CompilerConfig, context_header: str, source: str, trusted: bool = False,
                   source_name: str = "func.c") -> CompileResult:
    if not trusted:
        try:
            check_source(source)
        except SourceRejected as e:
            return CompileResult(False, None, f"rejected: {e}")

    with tempfile.TemporaryDirectory(prefix="dcore-") as tmp:
        work = Path(tmp)
        inc = work / "include"
        inc.mkdir()
        for d in cfg.include_dirs:
            shutil.copytree(d, inc, dirs_exist_ok=True)
        # LF on every platform: to the old GCCs a backslash before CRLF doesn't continue a line ("stray '\' in program")
        (inc / "context.h").write_text(context_header, encoding="utf-8", newline="\n")
        (work / source_name).write_text(f'#include "context.h"\n#line 1 "{source_name}"\n' + source + "\n",
                                        encoding="utf-8", newline="\n")

        root = _root(cfg, work)
        # placeholders may be compound tokens ("/Fo{obj}", "/I{include}"): substitute inside each
        subst = (("{src}", f"{root}/{source_name}"), ("{obj}", f"{root}/func.o"),
                 ("{include}", f"{root}/include"))
        argv = cfg.cmd
        for mark, value in subst:
            argv = [a.replace(mark, value) for a in argv]
        log = ""
        proc = None
        why = None
        for attempt in (1, 2, 3):
            try:
                with _SLOTS:
                    proc = _exec(cfg, work, argv, cfg.timeout,
                                 **({"outputs": ["func.o"], "stage": root} if _sandbox_mode(cfg) == "wsl" else {}))
            except subprocess.TimeoutExpired:
                if _sandbox_mode(cfg) == "docker":
                    return CompileResult(False, None,
                                         f"the compiler timed out inside the container after {cfg.timeout}s — this "
                                         "host emulates x86-64 with qemu (slow but stable); a large translation "
                                         "unit can exceed even that. Retry, or raise DOCKER_TIMEOUT.", infra=True)
                return CompileResult(False, None, f"compiler timed out after {cfg.timeout}s")
            log = (proc.stdout + proc.stderr).replace(root + "/", "")
            obj = work / "func.o"
            if proc.returncode == 0 and obj.exists():
                data = obj.read_bytes()
                if not valid_object(data):
                    why = (f"THE COMPILER WROTE AN INVALID OBJECT ({len(data)} bytes, no ELF/COFF/Mach-O "
                           f"header) — the toolchain crashed while emitting it; this is not your code. "
                           f"Retry; if it repeats, it is a compiler/Docker bug.")
                    try:
                        obj.unlink()
                    except OSError:
                        pass
                    if attempt < 3:
                        continue  # an intermittently dying toolchain often gets a clean write on retry
                    return CompileResult(False, None, why, infra=True)
                return CompileResult(True, data, log[-2000:])
            why = infra_crash(log)
            if why and attempt < 3:
                continue  # x86 translation crashes are intermittent: two clean retries
            break
        note = f"{why}\n\n" if why else ""
        return CompileResult(False, None, note + (log[-4000:] or f"compiler exited with {proc.returncode}"),
                             infra=bool(why))
