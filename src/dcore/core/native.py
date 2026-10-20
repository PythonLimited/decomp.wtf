"""Project glue for shipped binaries: import, analysis, plan, and the per-function judge.

The store-backed engine keeps claims, attempts and context; this adds what a program needs —
the compiler (user-definable, detected from the binary), the target view reconstructed from
the image by the platform pack, the judge, the registry tools, the analysis backends' seeds
and the briefs. Everything here is target-agnostic: the packs answer what an ELF or an x86 is.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import threading
import time
from pathlib import Path

from . import scoring
from .compiler import DOCKER_TIMEOUT, CompileResult, CompilerConfig, SourceRejected, check_header, compile_source
from ..targets import formats, plat_pack
from ..backends.ida import session as ida
from ..backends.ida import queries as ida_queries
from ..backends.ida import sweep as ida_export
from ..backends.ida.session import IdaError
from . import analyze as analyze_mod
from . import compilers, interfaces, judge
from . import target as target_mod
from .network import NetworkError, function_mode
from .engine import BASE_HEADER, _slugify

# A full recursive projection past this many lines is the whole engine, not this function's
# environment; rendering it makes context.h unparseable and dwarfing the function (reports
# #13/#23/#28/#33). The display projection (depth 3, 24 types) is the fallback.
_FULL_HEADER_MAX = 3000


def _sha1_file(path: Path) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _pe_tls_range(path: Path) -> tuple[int, int] | None:
    """(StartAddressOfRawData, EndAddressOfRawData) in VA space from a PE's TLS directory. These
    are the bounds the compiler's linked TLS offsets are relative to; the analysis symbols inside
    them are the thread-local variables whose offsets a relocatable object spells as SECREL + symbol."""
    try:
        with open(path, "rb") as f:
            dos = f.read(64)
            if dos[:2] != b"MZ":
                return None
            e_lfanew = int.from_bytes(dos[0x3C:0x40], "little")
            f.seek(e_lfanew)
            pe = f.read(24)
            if pe[:4] != b"PE\0\0":
                return None
            coff = pe[4:24]
            nsect = int.from_bytes(coff[2:4], "little")
            opt_size = int.from_bytes(coff[16:18], "little")
            opt_off = e_lfanew + 24
            f.seek(opt_off)
            opt = f.read(opt_size)
            magic = int.from_bytes(opt[0:2], "little")
            if magic not in (0x10B, 0x20B):
                return None
            is64 = magic == 0x20B
            dd_off = 112 if is64 else 96
            num_dd = int.from_bytes(opt[dd_off - 4:dd_off], "little")
            if num_dd <= 9:
                return None
            tls_rva = int.from_bytes(opt[dd_off + 9 * 8:dd_off + 9 * 8 + 4], "little")
            if not tls_rva:
                return None
            f.seek(opt_off + opt_size)
            sects = f.read(40 * nsect)

            def rva_to_off(rva: int) -> int | None:
                for i in range(nsect):
                    s = sects[i * 40:(i + 1) * 40]
                    va = int.from_bytes(s[12:16], "little")
                    vsize = int.from_bytes(s[8:12], "little")
                    rawsize = int.from_bytes(s[16:20], "little")
                    raw = int.from_bytes(s[20:24], "little")
                    if va <= rva < va + max(vsize, rawsize):
                        return raw + (rva - va)
                return None

            off = rva_to_off(tls_rva)
            if off is None:
                return None
            f.seek(off)
            d = f.read(40 if is64 else 24)
            if is64:
                start = int.from_bytes(d[0:8], "little")
                end = int.from_bytes(d[8:16], "little")
            else:
                start = int.from_bytes(d[0:4], "little")
                end = int.from_bytes(d[4:8], "little")
            return (start, end) if start and end else None
    except OSError:
        return None


def find_ida_database(binary: Path) -> Path | None:
    """An IDA database sitting next to the binary: `<name>.i64`, `<name>.idb`, or the stem form
    (`libfoo.so` -> `libfoo.i64`) — IDA's two usual save locations."""
    binary = Path(binary)
    for cand in (Path(str(binary) + ".i64"), Path(str(binary) + ".idb"),
                 binary.with_suffix(".i64"), binary.with_suffix(".idb")):
        if cand.is_file():
            return cand
    return None


def _object_kind(obj: bytes) -> str:
    """What a compiler just handed us, for the error message when it's the wrong format."""
    if obj[:4] == b"\x7fELF":
        return "an ELF object"
    if int.from_bytes(obj[:2], "little") in (0x8664, 0xAA64):
        return "a COFF object"
    if obj[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        return "a Mach-O object"
    return "an object of an unexpected format"


def friendly_ida_error(text: str) -> str | None:
    """The 1228-class open failure is almost always a database held by another IDA instance (the app
    itself opens the same .i64; IDA 9.4 refuses a second opener and dies with an internal error).
    Returns the user-facing explanation, or None when the error is something else."""
    if "1228" in text or "Oops! internal error" in text or "Failed to open database" in text:
        return ("the IDA database can't be opened right now: it is most likely open in another IDA "
                "instance (e.g. the IDA Professional app) — close it there (letting it save) and live "
                "seeds, lookups and write-through resume; matches and compiles are unaffected meanwhile")
    return None


class NativeEngine:
    def __init__(self, net):
        self.net = net
        self._analysis: dict[str, tuple[float, dict]] = {}  # slug -> (cache mtime, merged analysis)
        self._recons: dict[str, tuple[str, target_mod.Reconstructor]] = {}  # slug -> (sha, view builder)
        self._symbols: dict[str, tuple[str, object]] = {}  # slug -> (analysis sha, SymbolTable)
        self._fn_index: dict[str, tuple[str, dict[int, dict]]] = {}  # slug -> (sha, ea -> function)
        self._adj_key = None
        self._calls: dict[int, list[str]] = {}
        self._called_by: dict[int, list[str]] = {}
        self._ida = None  # ((slug, binary), IdaSession): one open worker for the current project
        self._ida_lock = threading.Lock()
        self._ida_dirty: float | None = None  # pending unsaved database writes
        self._header_fallbacks: dict[tuple[int, int], str] = {}  # (project, function) -> source-driven header

    # ------------------------------------------------------------------ import

    def create(self, workspace: Path, picked, *, ida_db: str | None = None, origin: Path | None = None,
               log=print) -> str:
        """Import a native program the user owns: identify it, copy it into a project folder and
        register a `native` project (analysis starts from the app). `ida_db` points the analysis at
        the user's own IDA database instead of paying auto-analysis again; `origin` is the file the
        user picked, where a database is looked for when none was named. Returns the slug."""
        info = picked.info
        workspace = Path(workspace)
        data = picked.data
        if isinstance(data, (bytes, bytearray)):
            sha1 = hashlib.sha1(bytes(data)).hexdigest()
        else:
            sha1 = _sha1_file(Path(data))
        for p in self.net.store.all("SELECT slug, config FROM projects"):
            cfg = json.loads(p["config"])
            if cfg.get("kind") == "native" and cfg.get("binary", {}).get("sha1") == sha1:
                log(f"already imported as {p['slug']}")
                return p["slug"]
        title = info.get("title") or "program"
        base = _slugify(title)
        slug, n = base, 2
        while self.net.store.one("SELECT 1 FROM projects WHERE slug=?", slug) or (workspace / slug).exists():
            slug, n = f"{base}-{n}", n + 1
        workdir = workspace / slug
        workdir.mkdir(parents=True)
        dest = workdir / Path(picked.filename).name
        if isinstance(data, (bytes, bytearray)):
            dest.write_bytes(bytes(data))
        else:
            try:
                os.link(data, dest)  # no second copy of a big binary when it's on the same drive
            except OSError:
                shutil.copyfile(data, dest)
        image = formats.identify_path(dest)
        size = dest.stat().st_size
        detected = None
        if not ida_db:
            here = origin or (Path(data) if isinstance(data, Path) else None)
            if here is not None:
                detected = find_ida_database(here)
        db = str(Path(ida_db).expanduser()) if ida_db else (str(detected) if detected else "")
        if db:
            log(f"IDA: the analysis will open {Path(db).name}, the existing database, instead of re-analyzing")
        cfg = {
            "kind": "native", "format": image.format, "arch": image.arch, "big_endian": False,
            "binary": {"file": dest.name, "sha1": sha1, "name": title, "size": size, "kind": image.kind},
            "image": image.to_dict(),
            "ida": {"database": db, "detected": bool(detected)},
            "compiler": {"guess": image.compiler, "command": "", "flags": []},
            "legal": {"basis": "personal-copy", "license": "personal use only",
                      "statement": "imported by the owner of this copy of the program",
                      "confirmed_at": time.time()},
            "context": {"file": None},
            "plan": None, "analysis": None,
        }
        now = time.time()
        with self.net.store.tx() as db:
            pid = db.execute("INSERT INTO projects(slug,name,description,arch,big_endian,root,config) "
                             "VALUES(?,?,?,?,?,?,?)",
                             (slug, title, formats.describe(image), image.arch, 0, str(workdir),
                              json.dumps(cfg))).lastrowid
            db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                       "VALUES(?,?,?,?,?,?,?)",
                       (pid, 1, BASE_HEADER.format(title=title), None, "basic types", now, ""))
            self.net._event(db, pid, None, "import", f"{formats.describe(image)}: {dest.name}")
        size_text = f"{size // (1024 * 1024)} MiB" if size >= 1 << 20 else f"{size // 1024} KiB"
        log(f"{formats.describe(image)}: {dest.name}, {size_text}")
        return slug

    # ------------------------------------------------------------------ state

    def overview(self, slug: str) -> dict:
        proj = self.net._project(slug)
        cfg = self.net.cfg(proj)
        # interface/excluded files are planned not to be decompiled: they are neither shown nor counted
        agg = self.net.store.one(
            "SELECT COUNT(*) AS total, SUM(status='matched') AS matched, SUM(size) AS bytes, "
            "SUM(CASE WHEN status='matched' THEN size ELSE 0 END) AS matched_bytes, SUM(attempts) AS attempts "
            "FROM functions WHERE project_id=? AND status IN ('open','matched')", proj["id"])
        ctx = self.net.store.one("SELECT MAX(version) AS v FROM context_versions WHERE project_id=?", proj["id"])
        b, image = cfg.get("binary", {}), cfg.get("image") or {}
        return {
            "slug": proj["slug"], "title": proj["name"], "description": proj["description"],
            "kind": "native", "platform": "native", "platform_name": "Native program", "compilers": [],
            "rom": None,
            "binary": {"name": b.get("name"), "format": cfg.get("format"), "arch": cfg.get("arch"),
                       "kind": b.get("kind"), "sha1": b.get("sha1"), "size": b.get("size"),
                       "compiler": cfg.get("compiler", {}).get("guess"), "debug": image.get("debug_kind"),
                       "sections": len(image.get("sections") or [])},
            "compiler": {"toolchain": "", "name": cfg.get("compiler", {}).get("guess") or "not resolved yet",
                         "flags": cfg.get("compiler", {}).get("flags") or [],
                         "command": cfg.get("compiler", {}).get("command") or "",
                         "installed": True, "proprietary": False, "supported": True},
            "functions": agg["total"] or 0, "matched": agg["matched"] or 0, "bytes": agg["bytes"] or 0,
            "matched_bytes": agg["matched_bytes"] or 0, "attempts": agg["attempts"] or 0,
            "context_version": ctx["v"] or 1,
            "folder": proj["root"], "export": cfg.get("export"), "exportable": bool(agg["matched"]),
            "ready": bool(cfg.get("plan")), "analysis": cfg.get("analysis"),
        }

    def info(self, slug: str) -> str:
        """What project_info (the agent tool) shows for a native project."""
        proj = self.net._project(slug)
        cfg = self.net.cfg(proj)
        ov = self.overview(slug)
        b = ov["binary"]
        lines = [f"{ov['title']} — {b['format'].upper()} {b['arch']} {b['kind']}, {b['size'] // 1024} KiB",
                 f"compiler: {ov['compiler']['name']}"
                 + (f" — driver: {ov['compiler']['command']}" if ov["compiler"].get("command") else "")
                 + (f", flags {' '.join(ov['compiler']['flags'])}" if ov["compiler"]["flags"] else "")]
        if not cfg.get("plan"):
            lines.append("state: analysis or plan missing — open decomp.wtf and run them there")
        else:
            lines.append(f"progress: {ov['matched']}/{ov['functions']} functions matched "
                         f"({100 * (ov['matched_bytes'] or 0) / (ov['bytes'] or 1):.1f}% of planned code)")
        return "\n".join(lines)

    # ------------------------------------------------------------------ build flags

    def probe(self, agent, slug: str, function: str, source: str, flags: str) -> str:
        """Try one function under different compiler flags — *nothing is recorded*. This is for finding the
        original build's optimization settings: a byte-identical probe means adopting those flags with
        set_build_flags() can record the match for real."""
        proj = self.net._project(slug)
        fn = self.net._function(function, slug)
        if fn["status"] == "matched":
            raise NetworkError(f"{fn['name']} is already matched; probes are for open functions")
        claim = self.net.store.one("SELECT agent_id FROM claims WHERE function_id=?", fn["id"])
        if claim and claim["agent_id"] != agent.id:
            raise NetworkError(f"{fn['name']} is claimed by someone else right now")
        wanted = shlex.split(flags or "")
        if not wanted:
            raise NetworkError('pass the flags to probe with, e.g. flags="-O2 -fno-strict-aliasing"')
        meta = json.loads(fn["meta"] or "{}")
        units = self.net._unit_contexts(proj["id"])
        header = self.net._context(proj["id"], self.net._effective_unit(fn, units))["header"]
        guessed = "c++" if compilers.guess_language(header) == "c++" else "c"
        language = "c++" if (meta.get("language") == "c++" or guessed == "c++") else "c"
        compiler = compilers.resolve(self.net, slug, language, unit=fn["unit"], cu=meta.get("cu"))
        header = self._render_header(fn, proj, header, source, language=language)
        # the probe's flags, spelled the driver's way (cl: /c /Fo — gcc: -c -o); template() is the
        # single source of that spelling
        import dataclasses

        probe = dataclasses.replace(compiler, flags=wanted)
        res = compile_source(CompilerConfig(cmd=probe.template(), timeout=DOCKER_TIMEOUT if compiler.sandbox == "docker" else 60,
                                            sandbox=compiler.sandbox, image=compiler.image,
                                            platform=compiler.platform),
                             header, self._self_declared(fn, source, header), source_name=compiler.source_name)
        if not res.ok and source.strip() and self._header_error(res.log):
            minimal = self._source_header(fn, proj, source, language)
            if minimal:
                retry = compile_source(CompilerConfig(cmd=probe.template(),
                                                      timeout=DOCKER_TIMEOUT if compiler.sandbox == "docker" else 60,
                                                      sandbox=compiler.sandbox, image=compiler.image,
                                                      platform=compiler.platform),
                                       minimal, self._self_declared(fn, source, minimal),
                                       source_name=compiler.source_name)
                if retry.ok:
                    res = retry
                    self._header_fallbacks[(proj["id"], fn["id"])] = minimal
        shown = " ".join(wanted)
        if not res.ok:
            if getattr(res, "infra", False):
                return (f"probe `{shown}`: the compiler did not run — infrastructure crash, not your flags or "
                        f"code.\n{res.log.strip()}")
            return f"probe `{shown}`: doesn't compile.\n{(res.log or '').strip()[:1200]}"
        cand, verdict, problems = self.evaluate(fn, proj, res.obj)
        if cand is None:
            bad = next((p for p in problems if p.startswith("THE COMPILED OBJECT IS NOT READABLE")), None)
            if bad:
                return f"probe `{shown}`: {bad}"
            return f"probe `{shown}`: compiled, but the function's symbol isn't in the object."
        target = self.target_obj(fn, proj)
        if target is None or verdict is None:
            return f"probe `{shown}`: compiled; couldn't judge it (no target view)."
        if verdict:
            return (f"probe `{shown}`: BYTE-IDENTICAL under these flags. Nothing was recorded — adopt them with "
                    f'set_build_flags("{shown}", function="{fn["name"]}") (saved on that function), then '
                    f"compile_and_diff again to record the match.")
        d = scoring.diff(target, cand)
        extra = ("\n" + "\n".join(problems)) if problems else ""
        body = d.render()
        if len(body) > 4000:
            body = body[:4000] + "\n…"
        return f"probe `{shown}`: score {max(1, d.score)} of {d.max_score} — nothing recorded.{extra}\n{body}"

    def set_flags(self, agent, slug: str, flags, function: str | None = None,
                  scope: str = "function") -> str:
        """Adopt compiler flags. With `function`, the default is a **per-function** override: probe the
        function under `compile_and_diff(flags=…)`, then save the winning set on that function alone.
        `scope="file"` pins the whole source file (the granularity the original build usually had);
        without `function` the flags become the project default.

        Detection is only a starting point: agents probe and adopt. Every matched function whose
        effective flags would change is recompiled, and the change is rejected if any stops matching,
        so "matched" always means byte-identical under flags the project still stores."""
        proj = self.net._project(slug)
        self.net._require_level(agent, "Changing the build flags")
        new = [str(f) for f in (flags if isinstance(flags, list) else shlex.split(str(flags or "")))]
        scope = (scope or "function").strip().lower()
        if scope not in ("function", "file"):
            return "❌ scope must be `function` (default) or `file`."
        cfg = self.net.cfg(proj)
        ccfg = cfg.get("compiler") or {}
        try:
            compilers.resolve(self.net, slug, "c")  # the driver must still resolve
        except NetworkError as e:
            return f"❌ REJECTED: {e}"
        matched_all = self.net.store.all("SELECT * FROM functions WHERE project_id=? AND status='matched'", proj["id"])
        units = self.net._unit_contexts(proj["id"])
        contexts: dict = {}  # materialized on demand: generating every unit's header here cost
                             # thousands of ~1s renders on a big project before any regression ran

        def header_for(fn):
            u = self.net._effective_unit(fn, units)
            if u not in contexts:
                contexts[u] = self.net._context(proj["id"], u)
            return contexts[u]["header"]

        def save(unit: str | None, value):
            def change(c):
                if unit is None:
                    c.setdefault("compiler", {})["flags"] = value
                    return
                units_cfg = c.setdefault("compiler", {}).setdefault("units", {})
                if value is None:
                    units_cfg.pop(unit, None)
                    if not units_cfg:
                        c["compiler"].pop("units", None)
                else:
                    units_cfg.setdefault(unit, {})["flags"] = value
            self.net._update_cfg(slug, change)

        if function and scope == "function":
            fn = dict(self.net._function(function, slug))
            meta = json.loads(fn["meta"] or "{}")
            old = meta.get("build_flags") if isinstance(meta.get("build_flags"), list) else None
            if old == new:
                shown = f"`{' '.join(new)}`" if new else "the file/project flags"
                return f"✅ {fn['name']} already compiles with {shown}."

            def save_fn(value):
                m = json.loads(fn["meta"] or "{}")
                if value is None:
                    m.pop("build_flags", None)
                else:
                    m["build_flags"] = value
                text = json.dumps(m, sort_keys=True)
                with self.net.store.tx() as db:
                    db.execute("UPDATE functions SET meta=? WHERE id=?", (text, fn["id"]))
                fn["meta"] = text

            save_fn(new or None)
            if fn["status"] == "matched":
                broken = self.net.regression_test(self.net._project(slug), None, only=[fn],
                                                  header_for=header_for)
                if broken:
                    save_fn(old)
                    listing = "\n".join(f"- {name}: {why}" for name, why in broken[:10])
                    return (f"❌ REJECTED: those flags break the matched function {fn['name']}; "
                            f"it keeps its previous flags.\n{listing}")
            with self.net.store.tx() as db:
                self.net._event(db, proj["id"], agent.id, "compiler",
                                f"{fn['name']}: function flags "
                                f"{' '.join(old) if old is not None else '(file/project)'} -> "
                                f"{' '.join(new) if new else '(file/project)'}")
            if not new:
                return (f"✅ cleared the per-function flags for {fn['name']}; it falls back to its file "
                        f"and project flags.")
            return (f"✅ {fn['name']} now compiles with `{' '.join(new)}` (saved on the function; its file "
                    f"and the project are unchanged).")

        if not new:
            return ("❌ refusing to clear the flags: pass them explicitly, e.g. `-O2`. An empty list builds at the "
                    "compiler default (-O0 for gcc/clang), which almost never matches an optimized game.")

        if function:  # per-file flags: the granularity the original build actually had
            fn = self.net._function(function, slug)
            unit = fn["unit"] or ""
            if not unit:
                return "❌ REJECTED: that function has no source file to attach flags to."
            label = unit.rsplit("/", 1)[-1]
            pinned = ((ccfg.get("units") or {}).get(unit) or {}).get("flags")
            old = [str(f) for f in pinned] if pinned is not None else None
            if old == new:
                return f"✅ {label} already compiles with `{' '.join(new)}`."
            affected = [f for f in matched_all if (f["unit"] or "") == unit]
            save(unit, new)
            broken = self.net.regression_test(self.net._project(slug), None, only=affected, header_for=header_for)
            if broken:
                save(unit, old)
                listing = "\n".join(f"- {name}: {why}" for name, why in broken[:10])
                return (f"❌ REJECTED: `{' '.join(new)}` breaks {len(broken)} matched function(s) in {label}; "
                        f"the file keeps its flags.\n{listing}")
            with self.net.store.tx() as db:
                self.net._event(db, proj["id"], agent.id, "compiler",
                                f"{label}: flags {' '.join(old) if old is not None else '(project default)'} -> "
                                f"{' '.join(new)}")
            return (f"✅ {label} now compiles with `{' '.join(new)}`"
                    + (f" (its {len(affected)} matched function(s) still match)." if affected else "."))

        old = [str(f) for f in (ccfg.get("flags") or [])]
        if old == new:
            return f"✅ the project flags are already `{' '.join(new) or '(none)'}`."
        pinned_units = {u for u, v in (ccfg.get("units") or {}).items() if (v or {}).get("flags") is not None}
        affected = [f for f in matched_all if (f["unit"] or "") not in pinned_units]  # pinned files keep their flags
        save(None, new)
        broken = self.net.regression_test(self.net._project(slug), None, only=affected, header_for=header_for)
        if broken:
            save(None, old)
            listing = "\n".join(f"- {name}: {why}" for name, why in broken[:10])
            return (f"❌ REJECTED: `{' '.join(new)}` breaks {len(broken)} matched function(s); the flags stay "
                    f"`{' '.join(old) or '(none)'}`.\n{listing}")
        with self.net.store.tx() as db:
            self.net._event(db, proj["id"], agent.id, "compiler",
                            f"flags: {' '.join(old) or '(none)'} -> {' '.join(new)}")
        parts = []
        if affected:
            parts.append(f"all {len(affected)} matched functions still match")
        if len(matched_all) > len(affected):
            parts.append(f"{len(matched_all) - len(affected)} keep their per-file flags")
        return f"✅ project build flags are now `{' '.join(new)}`" + (f" ({'; '.join(parts)})" if parts else "")

    # ------------------------------------------------------------------ data tools

    def read_data(self, slug: str, what: str, length: int = 64) -> str:
        """Hex dump of the imported binary at an address (0x…) or by function name — the native read_data."""
        proj = self.net._project(slug)
        data = (Path(proj["root"]) / self.net.cfg(proj)["binary"]["file"]).read_bytes()
        image = formats.identify(data)
        if image is None:
            raise NetworkError("the imported binary is gone or unreadable")
        what = (what or "").strip()
        addr = None
        label = ""
        analysis = self.analysis(proj) or {}
        if (m := re.match(r"^(?:0x)?([0-9A-Fa-f]{4,16})$", what)):
            addr = int(m.group(1), 16)
        elif (auto := re.match(r"^(?:loc|sub|byte|word|dword|qword|unk|off|flt|dbl)_([0-9A-Fa-f]{4,16})$", what)):
            # IDA's auto-names carry the address; the listing spells them everywhere even though the
            # sweep filters them out as auto-generated
            addr = int(auto.group(1), 16)
            label = what
        else:
            fn = next((f for f in analysis.get("functions", []) if what in (f.get("name"), f.get("display"))), None)
            if fn is None:  # the disassembly spells mangled names: `?foo@Bar@@…` must resolve too
                fn = next((f for f in analysis.get("functions", [])
                           if what in (f.get("linkage") or "", f.get("demangled") or "")), None)
            if fn is not None:
                addr = fn["ea"]
            else:  # a named global or static from the sweep - a static read is a symbol the code refers to
                rows = analysis.get("data") or []
                row = next((d for d in rows if d.get("name") == what), None) \
                    or next((d for d in rows if (d.get("name") or "").lower() == what.lower()), None)
                if row is not None:
                    addr = int(row["ea"])
                    label = row["name"] + (f": {row['type']}" if row.get("type") else "")
        if addr is None:
            hints: list[str] = []
            needle = what.lower()
            for d in analysis.get("data") or []:
                name = d.get("name") or ""
                if needle and needle in name.lower():
                    hints.append(name)
                    if len(hints) >= 5:
                        break
            if len(hints) < 5:
                for f in analysis.get("functions") or []:
                    for name in (f.get("demangled") or "", f.get("display") or ""):
                        if needle and needle in name.lower() and name not in hints:
                            hints.append(name)
                    if len(hints) >= 5:
                        break
            if not hints and what:
                # the leaf of a qualified or mangled spelling: `Class::enable_` won't substring-match
                # `?enable_@Class@@0_NA`, but its leaf does
                leaf = what.split("::")[-1].lstrip("?").split("@")[0].strip()
                if len(leaf) > 2:
                    for d in analysis.get("data") or []:
                        name = d.get("name") or ""
                        if leaf.lower() in name.lower():
                            hints.append(name)
                            if len(hints) >= 5:
                                break
            raise NetworkError(f"`{what}` is not an address, a function or a named global in this binary"
                               + (f" — close names: {', '.join(hints)}" if hints else ""))
        length = max(1, min(int(length), 512))
        sec = image.section_at(addr)
        chunk = formats.read_bytes(data, image, addr, length)
        head = f"0x{addr:08X}" + (f" {label}" if label else "") + (f" ({sec.name})" if sec is not None else "")
        if chunk is None:
            if sec is not None and sec.kind == "bss":
                return f"{head}: uninitialized data (.bss); zeros at load."
            return f"{head}: not in a loaded section."
        out = [head]
        for i in range(0, len(chunk), 16):
            part = chunk[i:i + 16]
            text = "".join(chr(c) if 32 <= c < 127 else "." for c in part)
            out.append(f"  {addr + i:08X}: {part.hex(' '):<47}  {text}")
        return "\n".join(out)

    # ------------------------------------------------------------------ the plan screen

    def compiler_view(self, slug: str) -> dict:
        """What the plan screen shows and edits: detected compiler, user overrides, any error."""
        cfg = self.net.cfg(self.net._project(slug))
        c = cfg.get("compiler") or {}
        guess = c.get("guess") or ""
        out = {"guess": guess, "command": c.get("command") or "",
               "image": c.get("image") or "",
               "image_ready": None, "image_platform": "", "suggested_image": "",
               "flags": [str(f) for f in (c.get("flags") or [])], "driver": "", "note": "", "error": None,
               "detected": ((cfg.get("analysis") or {}).get("compilers") or [])[:4]}
        if out["image"]:
            platform = compilers.image_platform(cfg, c)
            out["image_ready"] = compilers.image_present(out["image"], platform)  # the Pull button's state
            out["image_platform"] = platform or ""
            out["platform"] = c.get("platform") or ""
        else:
            built_with = (out["detected"][0].get("compiler") if out["detected"] else "") or guess
            out["suggested_image"] = compilers.suggested_image(built_with)
        try:
            resolved = compilers.resolve(self.net, slug, "c")
            out["driver"] = " ".join(resolved.command)
            out["note"] = resolved.note
        except NetworkError as e:
            out["error"] = str(e)
        return out

    def plan_view(self, slug: str) -> dict:
        """Everything the plan screen renders: file nodes with treatments, totals, compiler state."""
        from . import plan as plan_mod

        proj = self.net._project(slug)
        cfg = self.net.cfg(proj)
        binary = cfg.get("binary") or {}
        out = {"slug": slug, "title": proj["name"], "kind": "native",
               "binary": {"format": cfg.get("format"), "arch": cfg.get("arch"), "name": binary.get("name"),
                          "kind": binary.get("kind")},
               "analysis": cfg.get("analysis"), "compiler": self.compiler_view(slug),
               "confirmed": bool((cfg.get("plan") or {}).get("confirmed_at")),
               "analysis_stale": None, "nodes": [], "totals": {}, "error": None}
        analysis = self.analysis(proj)
        if analysis is None:
            out["error"] = "no analysis yet"
            return out
        try:  # one stat: does the database still match the stamp the analysis recorded?
            live = analyze_mod.db_stamp(Path(proj["root"]), cfg)
            stamped = (cfg.get("analysis") or {}).get("source_key") or ""
            if (stamped or live) and stamped != live:
                out["analysis_stale"] = ("the IDA database changed since this analysis — Analyze "
                                         "again to pick up its names and types")
        except Exception:
            pass
        files = analysis["graph"]["files"]
        by_ea = {f["ea"]: f for f in analysis["functions"]}
        plan = plan_mod.load(self.net, slug)
        suggested = plan_mod.suggested(analysis)
        treatments = plan_mod.effective(analysis, plan)
        deps = analysis["graph"].get("deps") or {}
        dependents = analysis["graph"].get("dependents") or {}
        unit_flags = (cfg.get("compiler") or {}).get("units") or {}
        counts = {"decompile": 0, "interface": 0, "exclude": 0}
        langs = {"c": 0, "c++": 0, "asm": 0}
        for path in sorted(files):
            node = files[path]
            fns = [by_ea[ea] for ea in node["functions"] if ea in by_ea]
            language = ("c++" if any((f.get("language") or "c") == "c++" for f in fns)
                        else "asm" if fns and all((f.get("language") or "c") == "asm" for f in fns) else "c")
            treatment = treatments[path]
            counts[treatment] = counts.get(treatment, 0) + 1
            langs[language] = langs.get(language, 0) + 1
            out["nodes"].append({
                "path": path, "name": Path(path).name or path, "dir": str(Path(path).parent),
                "functions": len(node["functions"]), "bytes": node["bytes"],
                "library": bool(fns) and node["library"] == len(node["functions"]),
                "library_functions": node["library"],
                "overrides": len((plan["nodes"].get(path) or {}).get("functions") or {}),
                "language": language, "treatment": treatment,
                "suggested": suggested.get(path, "decompile"),
                "deps": (deps.get(path) or [])[:60], "dependents": (dependents.get(path) or [])[:60],
                "flags": [str(f) for f in ((unit_flags.get(path) or {}).get("flags") or [])],
                "sample": [f.get("display") or f.get("name") for f in fns[:4] if f.get("name")],
            })
        out["totals"] = {"files": len(files), "functions": len(analysis["functions"]),
                         "bytes": sum((f.get("size") or 0) for f in analysis["functions"]),
                         "treatments": counts, "languages": langs,
                         "machinery": {kind: sum(1 for f in analysis["functions"] if f.get("glue") == kind)
                                       for kind in ("plt", "crt", "extern")}}
        out["glue"] = plan_mod.glue_treatment(plan)  # the one switch for the linker's own code
        if out["confirmed"]:
            rows = self.net.store.all(
                "SELECT status, COUNT(*) AS n FROM functions WHERE project_id=? GROUP BY status", proj["id"])
            out["functions"] = {r["status"]: r["n"] for r in rows}
        return out

    def signature_info(self, fn, proj) -> dict | None:
        """The declaration fields the Header tab's editor should start from. A class method comes
        from the registry (including const/static/virtual); a free function only has the parameter
        list in its display name, so the return type is left for the agent/user."""
        from . import registry as registry_mod

        name = fn["name"]
        base = name.split("(", 1)[0]
        inside = name.split("(", 1)[1].rsplit(")", 1)[0] if "(" in name else ""
        if "::" not in base:
            params = registry_mod._split_params(inside)
            return {"ret": "", "params": ", ".join(params), "const": False, "static": False,
                    "virtual": False}
        cls, member = base.rsplit("::", 1)
        analysis = self.analysis(proj)
        if analysis is None:
            return None
        entry = next((t for t in registry_mod.view(analysis, registry_mod.load(self.net, proj["slug"]))
                      if registry_mod.key_of(t) == cls), None)
        if entry is None:
            return None
        method = next((m for m in entry.get("methods") or [] if m.get("name") == member), None)
        if method is None:
            return None
        return {"ret": method.get("ret") or "",
                "params": ", ".join(method.get("params") or []),
                "const": bool(method.get("const")), "static": bool(method.get("static")),
                "virtual": bool(method.get("virtual"))}

    def type_hint(self, slug: str, name: str) -> str | None:
        """A class (or a data member) asked for as if it were a function: answer with the layout the
        registry gives (debug info + agent contributions), instead of a bare "no function"."""
        from . import interfaces
        from . import registry as registry_mod

        proj = self.net._project(slug)
        analysis = self.analysis(proj)
        if analysis is None:
            return None
        types = registry_mod.view(analysis, registry_mod.load(self.net, slug))
        want = (name or "").strip()
        for t in types:
            qualified = "::".join([*t["ns"], t["name"]])
            if want in (t["name"], qualified):
                block = interfaces.type_block({"types": [t]}, t["name"])
                return (f"'{want}' is a class, not a function — there is no code to decompile. The binary's "
                        f"debug info gives its layout:\n\n{block}\n\n"
                        f"write your source against that layout; the class's methods are separate functions")
        for t in types:
            qualified = "::".join([*t["ns"], t["name"]])
            for m in t.get("members") or []:
                if (m.get("name") or "") == want:
                    block = interfaces.type_block({"types": [t]}, t["name"])
                    return (f"'{want}' is a data member of class {qualified} (offset 0x{m['off']:x}) — not a "
                            f"function. Its class layout:\n\n{block}")
            if any((s.get("name") if isinstance(s, dict) else s) == want for s in t.get("statics") or []):
                block = interfaces.type_block({"types": [t]}, t["name"])
                return (f"'{want}' is a static data member of class {qualified} — not a function (nothing to "
                        f"decompile; declare it in your source as the class declares it). Its class layout:\n\n{block}")
        return None

    # ------------------------------------------------------------------ the type registry

    def get_type(self, slug: str, name: str) -> str:
        """One registry entry: the layout the code compiles against, where it came from, and who a
        change would re-verify. Bare names resolve only when unambiguous — ambiguity is shown."""
        from . import registry as registry_mod

        analysis = self.analysis(self.net._project(slug))
        if analysis is None:
            return "no analysis yet — analyze the project first"
        entries = registry_mod.view(analysis, registry_mod.load(self.net, slug))
        t = registry_mod.find(entries, name)
        if t is None:
            hits = registry_mod.candidates(entries, name)
            if len(hits) > 1:
                return (f"'{name}' matches {len(hits)} types — give the qualified name:\n"
                        + "\n".join(f"- {h}" for h in hits))
            near = registry_mod.search(entries, name, limit=8)
            lines = [f"no type '{name}' in the registry."]
            if near:
                lines.append("closest names:")
                lines += [f"- {registry_mod.key_of(x)}" for x in near]
            lines.append("add one with declare_type(name=..., kind=struct|class|union|enum, size=..., note=...) "
                         "then set_member for its fields (or the fields you know so far).")
            return "\n".join(lines)
        users = registry_mod.usage_by(self.net, slug, analysis, entries).get(t.get("name") or "", [])
        return registry_mod.describe(t, users)

    def search_types(self, slug: str, query: str = "", ns: str = "", member: str = "",
                     kind: str = "", used_by: str = "", limit: int = 20) -> str:
        """Find types: by name fragment, namespace, a member (name or type), kind, or the function
        that uses them ("what type is the self pointer sub_1234 handed me?"). Results say who uses
        each type and where it came from."""
        from . import registry as registry_mod

        analysis = self.analysis(self.net._project(slug))
        if analysis is None:
            return "no analysis yet — analyze the project first"
        entries = registry_mod.view(analysis, registry_mod.load(self.net, slug))
        users = None
        cap = int(limit or 20)
        if used_by:
            users = registry_mod.usage_by(self.net, slug, analysis, entries)
            probe = used_by.strip().lower()
            shots = registry_mod.search(entries, query, ns=ns, member=member, kind=kind, limit=10 ** 5)
            hits = [t for t in shots
                    if any(probe in fn.lower() for fn in users.get(t.get("name") or "", []))][:cap]
        else:
            hits = registry_mod.search(entries, query, ns=ns, member=member, kind=kind, limit=cap)
        if not hits:
            return ("nothing matches" + (f" '{query}'" if query else "") + (f" in {ns}" if ns else "")
                    + (f" with a member like '{member}'" if member else "")
                    + (f" used by '{used_by}'" if used_by else "")
                    + " — try a shorter fragment or fewer filters; an empty query lists the registry")
        users = users if users is not None else registry_mod.usage_by(self.net, slug, analysis, entries)
        lines = []
        for t in hits:
            n = len(users.get(t.get("name") or "", []))
            origin = "debug info" if t.get("origin") == "dwarf" else (t.get("origin") or "agent")
            bits = [f"{registry_mod.key_of(t)} — {t.get('kind')}"]
            if t.get("size"):
                bits.append(f"size 0x{int(t['size']):x}")
            bits.append(f"{len(t.get('members') or [])} member(s)")
            if t.get("decl"):
                bits.append("salvaged declaration")
            bits.append(f"used by {n} matched fn" if n else "unused yet")
            bits.append(origin)
            lines.append(" | ".join(bits))
        more = "" if len(hits) < int(limit or 20) else "\nnarrow with ns=/member=/kind= if you need more precision"
        return f"{len(hits)} type(s):\n" + "\n".join(lines) + f"\n{more}get_type for the full layout."

    def edit_type(self, agent, slug: str, action: str, session: str = "", **fields) -> str:
        """Propose one registry edit. Nothing is saved until every matched function whose compile
        environment changes is recompiled in the form it will live in and re-judged byte-identical;
        a rejected edit reports the functions that broke, a kept one re-checks how many functions.
        With `session` (a held lock_registry token) the edit is staged instead — validated now,
        verified once when the batch commits with unlock_registry."""
        from . import registry as registry_mod

        self.net._require_level(agent, "Editing the type registry")
        try:
            if session:
                res = registry_mod.stage(self.net, slug, session, action, fields)
                return (f"📝 staged: {action}{' — ' + res['note'] if res.get('note') else ''} — validated "
                        f"against the staged state; nothing is verified yet. Commit the whole batch with "
                        f"unlock_registry(session=…) (one verification for all staged edits), or discard it "
                        f"with action=\"abort\".")
            res = registry_mod.apply(self.net, slug, action, **fields)
        except registry_mod.RegistryError as e:
            return f"❌ {e}"
        note = f" — {res['note']}" if res.get("note") else ""
        if not res["ok"]:
            listing = "\n".join(f"- {f['name'][:70]}: {f['why'][:170]}" for f in res["failures"][:8])
            extra = f"\n(+{len(res['failures']) - 8} more)" if len(res["failures"]) > 8 else ""
            return (f"❌ REJECTED: {action}{note} breaks {len(res['failures'])} matched function(s); nothing was "
                    f"saved. Below is what those functions reported when recompiled against your change:\n"
                    f"{listing}{extra}\nAdjust the edit (or the code that uses it) and try again.")
        with self.net.store.tx() as db:
            self.net._event(db, self.net._project(slug)["id"], getattr(agent, "id", None), "types",
                            f"{action}{note} — {res['rechecked']} matched function(s) re-checked, "
                            f"{res.get('skipped', 0)} proven unchanged")
        sync = f" — {res['backend']}" if res.get("backend") else ""
        proven = f", {res['skipped']} proven unchanged without compiling" if res.get("skipped") else ""
        verified = max(0, res["rechecked"] - res.get("skipped", 0))
        return (f"✅ accepted: {action}{note} — {verified} matched function(s) re-checked byte-identical"
                f"{proven}, {len(res['units'])} header(s) refreshed{sync}. Every agent sees it on their next "
                f"compile. See the exact render with get_context(function=…).")

    def set_signature(self, agent, slug: str, function: str, ret: str, params: str = "",
                      const="", static="", virtual="", note: str = "") -> str:
        """Edit one function's declaration without touching its body: a class method goes through the
        gated registry (`set_method`), a free/namespace function replaces its prototype entry in the
        unit header. This is the first-class path for header-only functions, where there is no body
        to compile but callers still need the right spelling and mangling."""
        from . import entries as entries_mod
        from . import registry as registry_mod

        self.net._require_level(agent, "Editing a signature")
        fn = self.net._function(function, slug)
        proj = self.net._project(slug)
        base = fn["name"].split("(", 1)[0].strip()
        ret = (ret or "").strip()
        if not ret:
            return "❌ ret= is required (use `void` for no return value)"
        raw = (params or "").strip()
        plist = registry_mod._split_params(raw)
        truthy = lambda v: str(v or "").lower() in ("1", "true", "yes", "on")
        flags = {k for k, v in (("const", const), ("static", static), ("virtual", virtual)) if truthy(v)}
        if "::" in base:
            cls, member = base.rsplit("::", 1)
            analysis = self.analysis(proj)
            if analysis is None:
                return "❌ no analysis is loaded for this project"
            known = {registry_mod.key_of(t) for t in registry_mod.view(analysis, registry_mod.load(self.net, slug))}
            if cls in known:
                for bit in [ret, *plist]:
                    why = registry_mod.check_type(bit)
                    if why:
                        return f"❌ method type: {why}"
                current = self.signature_info(fn, proj) or {}
                current_flags = {k: bool(current.get(k)) for k in ("const", "static", "virtual")}
                desired_flags = {k: (truthy(v) if v not in (None, "") else current_flags[k])
                                 for k, v in (("const", const), ("static", static), ("virtual", virtual))}
                desired = {"ret": ret, "params": ", ".join(plist), **desired_flags}
                prefix = ("static " if desired_flags["static"] else "") + \
                         ("virtual " if desired_flags["virtual"] else "")
                suffix = " const" if desired_flags["const"] else ""
                probe_decl = (f"struct dcore_signature_probe_class {{ {prefix}{ret} {member}"
                              f"({', '.join(plist) if plist else 'void'}){suffix}; }};")
                probe = self._signature_probe(fn, proj, probe_decl)
                if not probe.ok:
                    return ("❌ signature does not compile: that type is not known in this header.\n"
                            + (probe.log or "")[:1200])
                if current and all(current.get(k) == v for k, v in desired.items()):
                    return f"✅ {fn['name']} already has that signature; nothing to do."
                return self.edit_type(agent, slug, "set_method", name=cls, member=member, mtype=ret,
                                      params=raw, const=const, static=static, virtual=virtual, note=note)
            if flags:
                return (f"❌ {cls!r} is not a known class, so {base} is treated as a namespace function; "
                        f"const/static/virtual only apply to a class method.")
        if flags:
            return f"❌ const/static/virtual only apply to a class method; {base} has no known class."
        declaration = f"{ret} {base}({', '.join(plist) if plist else 'void'});"
        unit = self.net._unit_of(proj, fn["name"])
        bare = base.rsplit("::", 1)[-1]
        old = next((e for e in entries_mod.list_for(self.net, slug, unit)
                    if e["name"] == bare and e["kind"] in ("prototype", "raw")), None)
        # edit_entries compiles the header with the new prototype on its own; a typo like `booll`
        # fails there before it can be saved.
        return self.net.edit_entries(agent, slug, remove=[old["id"]] if old else [],
                                     add=[{"kind": "prototype", "body": declaration}], function=fn["name"])

    def _signature_probe(self, fn, proj, source: str, overrides: dict | None = None):
        """Compile the declaration against the function's real generated header before committing it.
        `check_type` only proves a spelling is *syntactically* a type; it cannot know that `booll`
        exists. The gate only recompiles matched callers, so a header-only function with no callers
        would otherwise accept any typo."""
        meta = json.loads(fn["meta"] or "{}")
        units = self.net._unit_contexts(proj["id"])
        header = self.net._context(proj["id"], self.net._effective_unit(fn, units))["header"]
        language = "c++" if (meta.get("language") == "c++" or compilers.guess_language(header) == "c++") else "c"
        header = self._render_header(fn, proj, header, source, language=language, overrides=overrides)
        compiler = compilers.resolve(self.net, proj["slug"], language, unit=fn["unit"], cu=meta.get("cu"))
        res = compile_source(
            CompilerConfig(cmd=compiler.template(),
                           timeout=DOCKER_TIMEOUT if compiler.sandbox == "docker" else 60,
                           sandbox=compiler.sandbox, image=compiler.image, platform=compiler.platform),
            header, source + "\nint dcore_signature_probe_value;\n", source_name=compiler.source_name)
        return res

    def declare_opaque(self, agent, slug: str, name: str, decl: str = "", size="", align="",
                       trivial="", note: str = "") -> str:
        """Store a project-global opaque third-party declaration (prelude) or remove it with decl="".
        The prelude renders before every unit's type block, so a class method may name an alias such
        as `yield_context` without the real library headers. Gated: every matched function whose
        compiled header changes is recompiled and the declaration is rejected if one stops matching."""
        from . import registry as registry_mod

        self.net._require_level(agent, "Declaring an opaque type")
        proj = self.net._project(slug)
        name = (name or "").strip()
        if not name:
            return "❌ name= is required, e.g. name=\"boost::asio::yield_context\""
        data = registry_mod.load(self.net, slug)
        old = (data.get("opaque") or {}).get(name)
        decl = (decl or "").strip()
        candidate = json.loads(json.dumps(data))
        opaque = candidate.setdefault("opaque", {})
        if not decl:
            if old is None:
                return f"❌ no opaque declaration named {name!r}"
            opaque.pop(name, None)
        else:
            try:
                check_header(decl)
            except SourceRejected as e:
                return f"❌ {e}"
            entry = {"decl": decl, "origin": "agent", "updated": time.time()}
            for label, value in (("size", size), ("align", align)):
                if value not in (None, ""):
                    try:
                        entry[label] = int(value)
                    except (TypeError, ValueError):
                        return f"❌ {label}={value!r} is not a number of bytes"
            if trivial not in (None, ""):
                if str(trivial).lower() in ("1", "true", "yes", "on"):
                    entry["trivial"] = True
                elif str(trivial).lower() in ("0", "false", "no", "off"):
                    entry["trivial"] = False
                else:
                    return "❌ trivial= must be true or false"
            if note:
                entry["note"] = note.strip()
            opaque[name] = entry
        if candidate == data:
            return f"✅ {name} already has that opaque declaration."
        analysis = self.analysis(proj)
        if analysis is None:
            return "❌ no analysis is loaded for this project"
        _, by_unit, units_set = registry_mod._matched_context(self.net, proj)
        gate = registry_mod._gate(self.net, slug, proj, analysis, by_unit, units_set, data, candidate)
        if gate["failures"]:
            listing = "\n".join(f"- {f['name'][:70]}: {f['why'][:150]}" for f in gate["failures"][:8])
            return (f"❌ REJECTED: opaque {name!r} breaks {len(gate['failures'])} matched function(s); "
                    f"nothing was saved.\n{listing}")
        registry_mod.save(self.net, slug, candidate)
        registry_mod._refresh(self.net, slug, proj, analysis, gate["touched"], by_unit, "opaque declaration")
        with self.net.store.tx() as db:
            self.net._event(db, proj["id"], getattr(agent, "id", None), "types",
                            f"opaque {name}: {'removed' if not decl else 'declared'} — "
                            f"{gate['checked']} matched function(s) checked")
        return (f"✅ opaque {name!r} {'removed' if not decl else 'declared'} project-globally — "
                f"{gate['checked']} matched function(s) re-checked, {len(gate['touched'])} header(s) refreshed. "
                f"It renders before every type block; the next compile of a caller sees it.")

    def lock_registry(self, agent, slug: str, wait: float = 120) -> str:
        """Take the registry for a batch of related edits: stage several with
        edit_type(session=…), then unlock_registry — the whole batch is verified in *one* pass
        instead of one gate run per edit. Other agents' edits wait their turn while you hold it,
        and the lease expires by itself if you go quiet."""
        from . import registry as registry_mod

        self.net._require_level(agent, "Editing the type registry")
        res = registry_mod.lock(self.net, slug, agent, wait)
        proj = self.net._project(slug)
        if not res["ok"]:
            return (f"⏳ {res['busy']} has the registry locked right now (expires in "
                    f"{int(max(0, res['expires'] - time.time()))}s) — no session for you yet. Try again, or "
                    f"make a single edit_type: those wait for the lock on their own.")
        with self.net.store.tx() as db:
            self.net._event(db, proj["id"], getattr(agent, "id", None), "context",
                            "locked the type registry for a batch"
                            + (" (took over an expired session)" if res.get("took_over") else ""))
        return (f"🔒 the registry is yours (session {res['token']}). Stage edits with "
                f"edit_type(..., session=\"{res['token']}\") — each is validated immediately but not verified "
                f"yet; unlock_registry(session=\"{res['token']}\") verifies the whole batch once and commits. "
                f"The lock expires by itself in ~10 minutes of silence.")

    def unlock_registry(self, agent, slug: str, session: str, action: str = "commit") -> str:
        """End a registry session: commit verifies the staged batch (rejected batches stay staged
        so they can be fixed and committed again), abort discards it unverified."""
        from . import registry as registry_mod

        self.net._require_level(agent, "Editing the type registry")
        proj = self.net._project(slug)
        try:
            res = registry_mod.unlock(self.net, slug, session, commit=(action != "abort"))
        except registry_mod.RegistryError as e:
            return f"❌ {e}"
        if res.get("aborted"):
            with self.net.store.tx() as db:
                self.net._event(db, proj["id"], getattr(agent, "id", None), "context",
                                f"aborted a registry session ({res['discarded']} staged type(s) discarded)")
            return f"🔓 aborted — {res['discarded']} staged change(s) discarded; nothing was verified."
        if not res["ok"]:
            listing = "\n".join(f"- {f['name'][:70]}: {f['why'][:170]}" for f in res["failures"][:8])
            extra = f"\n(+{len(res['failures']) - 8} more)" if len(res["failures"]) > 8 else ""
            return (f"❌ REJECTED: the batch{' — ' + res['note'] if res.get('note') else ''} breaks "
                    f"{len(res['failures'])} matched function(s); your staged edits are kept (the lock is still "
                    f"yours) — fix or drop them with more edit_type(session=…) calls, then unlock_registry "
                    f"again, or unlock_registry(action=\"abort\"). Below is what those functions reported when "
                    f"recompiled against your change:\n{listing}{extra}")
        with self.net.store.tx() as db:
            self.net._event(db, proj["id"], getattr(agent, "id", None), "types",
                            f"session commit{' — ' + res['note'] if res.get('note') else ''} — "
                            f"{res['rechecked']} matched function(s) re-checked, "
                            f"{res.get('skipped', 0)} proven unchanged")
        sync = f" — {res['backend']}" if res.get("backend") else ""
        proven = f", {res['skipped']} proven unchanged without compiling" if res.get("skipped") else ""
        verified = max(0, res["rechecked"] - res.get("skipped", 0))
        return (f"🔓 committed{' — ' + res['note'] if res.get('note') else ''} — {verified} matched "
                f"function(s) re-checked byte-identical{proven}, {len(res['units'])} header(s) refreshed{sync}. "
                f"Every agent sees it on their next compile. See the exact render with get_context(function=…).")

    def unit_functions(self, slug: str, path: str) -> dict:
        """One unit's functions with their effective treatments — the leaves the plan tree opens
        into, so every file (and the 'no debug info' rest) can be picked from function by function."""
        from . import plan as plan_mod

        proj = self.net._project(slug)
        analysis = self.analysis(proj)
        if analysis is None:
            return {"path": path, "functions": []}
        files = analysis["graph"]["files"]
        if path not in files:
            return {"path": path, "functions": []}
        by_ea = {f["ea"]: f for f in analysis["functions"]}
        plan = plan_mod.load(self.net, slug)
        default = plan_mod.effective(analysis, plan).get(path, "decompile")
        overrides = plan_mod.function_overrides(plan)
        glue = plan_mod.glue_treatment(plan)
        status = {r["vram"]: r["status"] for r in self.net.store.all(
            "SELECT vram, status FROM functions WHERE project_id=? AND unit=?", proj["id"], path)}
        out = []
        for ea in files[path]["functions"]:
            fn = by_ea.get(ea)
            if fn is None:
                continue
            cls = fn.get("glue") or ""
            out.append({"name": fn.get("display") or fn.get("name") or f"sub_{ea:x}", "ea": ea,
                        "size": fn["size"], "lib": bool(fn.get("lib")), "glue": cls,
                        "treatment": overrides.get((path, ea)) or (glue if cls else None) or default,
                        "status": status.get(ea)})
        out.sort(key=lambda f: (-f["size"], f["name"]))
        return {"path": path, "functions": out}

    def find_functions(self, slug: str, q: str = "", limit: int = 200) -> dict:
        """Search every function the analysis knows, by name fragment or address — the plan's search
        finds leaves, not just files. Each hit carries its file, treatment and status, so the plan
        (or an agent) can act on it without unfolding anything."""
        from . import plan as plan_mod

        proj = self.net._project(slug)
        analysis = self.analysis(proj)
        query = (q or "").strip().lower()
        if analysis is None or not query:
            return {"total": 0, "functions": []}
        files = analysis["graph"]["files"]
        by_ea = {f["ea"]: f for f in analysis["functions"]}
        plan = plan_mod.load(self.net, slug)
        default = plan_mod.effective(analysis, plan)
        overrides = plan_mod.function_overrides(plan)
        glue = plan_mod.glue_treatment(plan)
        status = {r["vram"]: r["status"] for r in self.net.store.all(
            "SELECT vram, status FROM functions WHERE project_id=?", proj["id"])}
        hexq = (query[2:] if query.startswith("0x") else
                query if len(query) >= 4 and all(c in "0123456789abcdef" for c in query) else None)
        hits = []
        for path, node in files.items():
            for ea in node["functions"]:
                fn = by_ea.get(ea)
                if fn is None:
                    continue
                vram = fn.get("vram") or ea
                if hexq is not None:
                    if not f"{vram:x}".startswith(hexq):
                        continue
                else:
                    name = fn.get("display") or fn.get("name") or ""
                    if query not in name.lower():
                        continue
                cls = fn.get("glue") or ""
                hits.append({
                    "name": fn.get("name") or fn.get("display") or f"sub_{ea:x}",
                    "display": fn.get("display") or fn.get("name") or f"sub_{ea:x}",
                    "ea": ea, "vram": vram, "size": fn.get("size") or 0, "unit": path,
                    "lib": bool(fn.get("lib")), "glue": cls,
                    "treatment": (overrides.get((path, ea)) or (glue if cls else None)
                                  or default.get(path, "decompile")),
                    "status": status.get(vram),
                })
        hits.sort(key=lambda f: (f["display"].lower(), f["ea"]))
        return {"total": len(hits), "functions": hits[:max(1, limit)]}

    # ------------------------------------------------------------------ caches

    def analysis(self, proj) -> dict | None:
        """The merged analysis, loaded once per cache change (keyed by the file's mtime)."""
        slug = proj["slug"]
        path = Path(proj["root"]) / (self.net.cfg(proj).get("analysis") or {}).get(
            "file", ".decomp-wtf/native/analysis.json")
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return None
        cached = self._analysis.get(slug)
        if cached and cached[0] == mtime:
            return cached[1]
        data = analyze_mod.load(self.net, slug)
        if data is None:
            return None
        self._analysis[slug] = (mtime, data)
        return data

    def symbol_table(self, proj):
        """The shared name/address view over the current analysis (cached by sha256)."""
        from . import symbols as symbols_mod

        analysis = self.analysis(proj)
        if analysis is None:
            return None
        slug, sha = proj["slug"], str(analysis.get("sha256") or "")
        # `proj` may be a row captured before an alias edit; read the current config.
        fresh = self.net.project_row(slug)
        cfg = self.net.cfg(fresh)
        aliases = {str(k): int(v) for k, v in ((cfg.get("symbol_aliases") or {}).items())}
        data_aliases = {str(k): int(v) for k, v in ((cfg.get("data_aliases") or {}).items())}
        cache_key = (sha + json.dumps(aliases, sort_keys=True)
                     + json.dumps(data_aliases, sort_keys=True))
        cached = self._symbols.get(slug)
        if cached and cached[0] == cache_key:
            return cached[1]
        table = symbols_mod.SymbolTable.from_analysis(analysis, aliases=aliases,
                                                      data_aliases=data_aliases)
        self._symbols[slug] = (cache_key, table)
        return table

    def name_function(self, agent, proj, name: str, address: str | int, note: str = "") -> str:
        """Give an address a symbol spelling the judge can resolve (an alias, not a rename)."""
        name = (name or "").strip()
        if not name:
            raise NetworkError("name_function needs a non-empty name")
        try:
            ea = int(str(address), 0)
        except (TypeError, ValueError):
            raise NetworkError(f"invalid address {address!r}") from None
        if ea <= 0:
            raise NetworkError("address must be positive")
        table = self.symbol_table(proj)
        existing = table.resolve_code(name) if table is not None else None
        if existing is not None and existing != ea:
            raise NetworkError(f"{name} already resolves to 0x{existing:x}; choose another name")
        self.net._update_cfg(proj["slug"],
                             lambda cfg: cfg.setdefault("symbol_aliases", {}).__setitem__(name, ea))
        self._symbols.pop(proj["slug"], None)
        return f"named {name} at 0x{ea:x}" + (f" ({note})" if note else "")

    def name_data(self, agent, proj, name: str, address: str | int, note: str = "") -> str:
        """Give an unnamed data address the spelling the rebuilt header uses."""
        name = (name or "").strip()
        if not name:
            raise NetworkError("name_data needs a non-empty name")
        try:
            ea = int(str(address), 0)
        except (TypeError, ValueError):
            raise NetworkError(f"invalid address {address!r}") from None
        if ea <= 0:
            raise NetworkError("address must be positive")
        table = self.symbol_table(proj)
        existing = table.resolve_data(name) if table is not None else None
        if existing is not None and existing != ea:
            raise NetworkError(f"{name} already resolves to 0x{existing:x}; choose another name")
        self.net._update_cfg(proj["slug"],
                             lambda cfg: cfg.setdefault("data_aliases", {}).__setitem__(name, ea))
        self._symbols.pop(proj["slug"], None)
        return f"named data {name} at 0x{ea:x}" + (f" ({note})" if note else "")

    def strict_rejudge(self, proj, limit: int | None = None) -> str:
        """Re-run every matched function against the current judge without changing its status."""
        rows = self.net.store.all(
            "SELECT * FROM functions WHERE project_id=? AND status='matched' ORDER BY id", proj["id"])
        if limit:
            rows = rows[:int(limit)]
        failures: list[str] = []
        for fn in rows:
            source = fn["matched_source"] or ""
            if not source:
                failures.append(f"{fn['name']}: no matched source")
                continue
            result = self.compile_fn(fn, proj, self.header_view(fn, proj), source, raw_header=True)
            if not result.ok:
                failures.append(f"{fn['name']}: no longer compiles: {result.log[-300:]}")
                continue
            _cand, verdict, problems = self.judge(fn, proj, result.obj)
            if verdict is None or not verdict.match:
                failures.append(f"{fn['name']}: {verdict.score if verdict else '?'} "
                                f"{'; '.join(problems[:2])}")
        head = f"strict rejudge: {len(rows)} matched, {len(failures)} failed"
        return head + ("\n" + "\n".join(failures[:20]) if failures else "")

    def analysis_function(self, proj, fn) -> dict | None:
        """The merged-analysis record for a DB function row (keyed by its vram)."""
        analysis = self.analysis(proj)
        if analysis is None:
            return None
        slug, sha = proj["slug"], str(analysis.get("sha256") or "")
        cached = self._fn_index.get(slug)
        if not cached or cached[0] != sha:
            cached = (sha, {f["ea"]: f for f in analysis.get("functions") or []})
            self._fn_index[slug] = cached
        try:
            ea = fn["vram"]
        except (KeyError, TypeError):
            ea = fn.get("vram") if isinstance(fn, dict) else None
        return cached[1].get(ea) if ea is not None else None

    def reconstructor(self, proj) -> target_mod.Reconstructor | None:
        analysis = self.analysis(proj)
        if analysis is None:
            return None
        slug, sha = proj["slug"], analysis.get("sha256")
        cached = self._recons.get(slug)
        if cached and cached[0] == sha:
            return cached[1]
        cfg = self.net.cfg(proj)
        data = (Path(proj["root"]) / cfg["binary"]["file"]).read_bytes()
        image = formats.identify(data)
        if image is None:
            return None
        functions = {f["ea"]: {"name": f.get("name"), "display": f.get("display")} for f in analysis["functions"]}
        strings = {s["ea"]: s["text"] for s in analysis.get("strings") or []}
        imports = {im["ea"]: im["name"] for im in analysis.get("imports") or []}
        data_names = {int(d["ea"]): d["name"] for d in analysis.get("data") or [] if d.get("name")}
        rc = target_mod.Reconstructor(data, image, functions, strings, imports, data_names=data_names)
        self._recons[slug] = (sha, rc)
        return rc

    def adjacency(self, proj):
        """(calls, called_by) keyed by address, built once per analysis."""
        analysis = self.analysis(proj)
        if analysis is None:
            return {}, {}
        key = (proj["slug"], analysis.get("sha256"))
        if key != self._adj_key:
            by_ea = {f["ea"]: f for f in analysis["functions"]}
            calls: dict[int, list[str]] = {}
            called_by: dict[int, list[str]] = {}
            for edge in analysis.get("edges") or []:
                src = by_ea.get(edge.get("ea"))
                if src is None:
                    continue
                for to in edge.get("to", []):
                    dst = by_ea.get(to)
                    if dst is None:
                        continue
                    calls.setdefault(src["ea"], []).append(dst.get("display") or dst.get("name") or "?")
                    called_by.setdefault(dst["ea"], []).append(src.get("display") or src.get("name") or "?")
            self._adj_key, self._calls, self._called_by = key, calls, called_by
        return self._calls, self._called_by

    # ------------------------------------------------------------------ the loop

    def _self_declared(self, fn, source: str, header: str = "") -> str:
        """MSVC refuses a qualified definition (`Ret Ns::f(...) { }`) with no prior declaration
        (C2039), and it will not even accept a qualified *declaration* from outside the namespace -
        the prototype must sit inside it. The prototype assembles from the debug info's two halves
        (`signature`: `unsigned __int64 __fastcall()`, `demangled`: `Ns::f(void)`) and is wrapped in
        the namespace chain, unless that chain walks through a registered type - a class member can
        only be declared by the class itself (the registry's job)."""
        if fn is None:
            return source
        try:
            meta = json.loads(fn["meta"] or "{}")
        except (TypeError, ValueError):
            return source
        dm = (meta.get("demangled") or "").strip()
        sig = (meta.get("signature") or "").strip()
        tail = dm
        for suffix in (" const", " volatile", " noexcept", " override", " final"):
            if tail.endswith(suffix):
                tail = tail[: -len(suffix)]
        if not dm or "(" not in dm or not tail.endswith(")"):
            return source
        ret = sig[: sig.rfind("(")].strip() if "(" in sig else ""
        if not ret:
            return source
        head = dm[: dm.rfind("(")]
        qprefix = head.rsplit("::", 1)[0] if "::" in head else ""
        name_part = dm[len(qprefix) + 2:] if qprefix else dm
        if not qprefix:
            return f"{ret} {dm};\n{source}"
        if "<" in qprefix or ")" in qprefix:  # template spells of the scope: don't guess
            return source
        parts = qprefix.split("::")
        if self._class_path(fn, parts):
            return source
        # A hidden registry type may still be hand-declared in the editable/frozen header
        # (DefaultPrintFunction): wrapping the prototype in `namespace DefaultPrintFunction`
        # then collides with the struct (C2757). The class declaration already scopes the member.
        if header and re.search(rf"\b(?:class|struct|union)\s+{re.escape(parts[-1])}\b", header):
            return source
        proto = "namespace " + " { namespace ".join(parts) + " { " + f"{ret} {name_part};" + "}" * len(parts)
        return f"{proto}\n{source}"

    def _class_path(self, fn, parts: list[str]) -> bool:
        """Whether a qualified name walks through a registered type (so its last scope is a class,
        not a namespace)."""
        try:
            proj = self.net.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
            analysis = self.analysis(proj)
        except Exception:
            return False
        if analysis is None:
            return False
        from . import registry
        keys = {registry.key_of(t) for t in registry.view(analysis, registry.load(self.net, proj["slug"]))}
        path = ""
        for part in parts:
            path = f"{path}::{part}" if path else part
            if path in keys:
                return True
        return False

    def has_callers(self, fn, proj) -> bool:
        """Whether anything in the analysis calls this function. A zero-xref function gets the
        compact unit header instead of the recursive whole-registry projection: the projection was
        called 'the callee environment' but for a function nobody calls it only pulls the engine's
        stale closure and fails to parse (reports #13/#23/#28/#33)."""
        cache = getattr(self, "_called_targets", None)
        if cache is None or cache[0] != proj["id"]:
            called: set[int] = set()
            for e in (self.analysis(proj) or {}).get("edges") or []:
                to = e.get("to")
                if isinstance(to, (list, tuple)):
                    called.update(int(x) for x in to)
                elif to:
                    called.add(int(to))
            cache = self._called_targets = (proj["id"], called)
        return int(fn["vram"] or 0) in cache[1]

    def _unit_entries_text(self, proj, fn) -> str:
        """The unit's live structured entries, rendered: every compile of the unit carries them.
        Stored text headers are the legacy layer; entries are the editable layer going forward."""
        if fn is None:
            return ""
        from . import entries as entries_mod

        unit = self.net._effective_unit(fn, self.net._unit_contexts(proj["id"]))
        return "\n".join(entries_mod.render(entries_mod.list_for(self.net, proj["slug"], unit)))

    def _render_header(self, fn, proj, header: str, source: str, *, language: str | None = None,
                       raw_header: bool = False, overrides: dict | None = None) -> str:
        """The header a compile of `fn` sees: the unit's entries first, then the legacy visible part,
        then the registry's recursive projection for everything the header and `source` name. compile_fn,
        probe and the context view all come through here, so what an agent reads is what compiles."""
        meta = json.loads(fn["meta"] or "{}") if fn is not None else {}
        guessed = "c++" if compilers.guess_language(header) == "c++" else "c"
        if language is None:
            language = "c++" if (meta.get("language") == "c++" or guessed == "c++") else "c"
        entries_text = self._unit_entries_text(proj, fn) if not raw_header else ""
        if not raw_header and language == "c++":
            analysis = self.analysis(proj)
            if analysis is not None:
                from . import registry
                if overrides is None:
                    overrides = registry.load(self.net, proj["slug"])
                # The callee environment is useful, but a full closure can become the whole engine
                # (Allocate reaches String/Malloc/instances: 8.5k lines, C2011/C2059). Render it
                # when it is a real environment; fall back to the types the source names otherwise.
                # This is the same header get_context shows, so the view and the compile agree.
                full = not (fn is not None and not self.has_callers(fn, proj))
                # Compile against this function's callees, not every callee in the unit: a
                # unit-wide context seeded the type closure with dozens of unrelated classes.
                fctx = None
                if fn is not None:
                    afn = self.analysis_function(proj, fn)
                    if afn is not None:
                        from . import interfaces

                        fctx = "\n".join(interfaces.function_context(analysis, afn, language="c++"))
                base = fctx if fctx is not None else header
                legacy = interfaces.strip_types(header) if fctx is not None else ""
                header = registry.header_for(
                    analysis, base, source, overrides,
                    inline_defs=registry.header_defs(self.net, proj["slug"], analysis, overrides),
                    salvaged=registry.salvage_entries(self.net, proj["slug"], analysis, overrides,
                                                      [base, source],
                                                      declared=registry.declared_names(base)),
                    skip=registry.def_key(meta, fn["name"] if fn is not None else ""),
                    entries=entries_text, legacy=legacy, full=full,
                    prelude=registry.opaque_text(overrides))
                if full and len(header.splitlines()) > _FULL_HEADER_MAX:
                    # entries are the live declaration layer; the frozen legacy text still carries
                    # definitions the entries were promoted from (C2011 on OSMemory, vector, …).
                    # For an engine-wide closure, compile against the entries + source types only.
                    # The legacy inline new/delete are not type definitions and some units' sources
                    # use placement new: keep them (String::SplitWithQuat) while dropping the types.
                    legacy = header
                    header = registry.header_for(
                        analysis, "", source, overrides,
                        inline_defs=registry.header_defs(self.net, proj["slug"], analysis, overrides),
                        salvaged=registry.salvage_entries(self.net, proj["slug"], analysis, overrides,
                                                          [header, source],
                                                          declared=registry.declared_names(header)),
                        skip=registry.def_key(meta, fn["name"] if fn is not None else ""),
                        entries=entries_text, full=False,
                        prelude=registry.opaque_text(overrides))
                    ops = [line for line in legacy.splitlines()
                           if "operator new" in line or "operator delete" in line]
                    if ops:
                        header = header.rstrip() + "\n\n" + "\n".join(ops) + "\n"
            elif entries_text:
                from . import interfaces

                header = entries_text + "\n\n" + interfaces.strip_types(header).rstrip() + "\n"
        elif not raw_header and entries_text:
            from . import interfaces

            # C needs its generated struct layouts at compile time: unlike C++ there is no registry
            # projection to rebuild them from the source. Keep the block; only C++ re-projects.
            if language == "c++":
                header = entries_text + "\n\n" + interfaces.strip_types(header).rstrip() + "\n"
            else:
                header = entries_text + "\n\n" + header.rstrip() + "\n"
        return header

    @staticmethod
    def _header_error(log: str | None) -> bool:
        """Did the compiler fail before the submission? Every generated header is context.h; a source
        error names func.cpp. This is what makes the fallback target-agnostic: DWARF, PDB, stripped or
        an old stored context all fail the same way."""
        log = log or ""
        return "context.h:" in log and ("error:" in log or "fatal error:" in log)

    def _source_header(self, fn, proj, source: str, language: str = "c++") -> str:
        """A minimal header seeded only by the source: entries plus the registry's types for names
        the submission uses. No frozen type text, no unrelated callees. This is the last-resort
        header when the stored unit header does not parse."""
        analysis = self.analysis(proj)
        if analysis is None:
            return ""
        entries_text = self._unit_entries_text(proj, fn)
        if language == "c":
            # C has no registry projection: regenerate the unit's clean C header (struct layouts +
            # prototypes) and put the live entries in front. This is still format-agnostic; the
            # generator reads the target profile from the analysis.
            if fn is None or not fn["unit"]:
                return entries_text
            from . import interfaces

            fresh = interfaces.unit_header(analysis, fn["unit"], language="c")
            return (entries_text + "\n\n" + fresh) if entries_text else fresh
        from . import registry

        overrides = registry.load(self.net, proj["slug"])
        meta = json.loads(fn["meta"] or "{}") if fn is not None else {}
        return registry.header_for(
            analysis, "", source, overrides,
            inline_defs=registry.header_defs(self.net, proj["slug"], analysis, overrides),
            salvaged=registry.salvage_entries(self.net, proj["slug"], analysis, overrides, [source],
                                              declared=registry.declared_names(source)),
            skip=registry.def_key(meta, fn["name"] if fn is not None else ""),
            entries=entries_text, full=False,
            prelude=registry.opaque_text(overrides))

    def header_view(self, fn, proj) -> str:
        """The header this function's next compile will get, rendered by the compile pipeline itself:
        entries, legacy visible text, then the fresh projection seeded by the function's current source.
        `get_context` returns this so an agent can see what its declarations and edits changed."""
        fallback = self._header_fallbacks.get((proj["id"], fn["id"]))
        if fallback:
            return fallback
        units = self.net._unit_contexts(proj["id"])
        header = self.net._context(proj["id"], self.net._effective_unit(fn, units))["header"]
        source = fn["matched_source"] or fn["best_source"] or ""
        if not source:
            # failed attempts never become best_source; the latest submission is still the source the
            # projection will see (and the one that exposed a broken header). Preview the real thing.
            row = self.net.store.one("SELECT source FROM attempts WHERE function_id=? ORDER BY id DESC LIMIT 1",
                                     fn["id"])
            source = (row["source"] if row else "") or ""
        return self._render_header(fn, proj, header, source)

    def compile_fn(self, fn, proj, header: str, source: str, *, raw_header: bool = False):
        """Compile one submitted function with the project's (or the detected) compiler — and make sure
        the object it produced is the *format the project is*: a Mach-O .o where an ELF one belongs is
        reported here, with a fix, instead of surfacing as a pyelftools error three layers down.

        Unless `raw_header`, the header is generated for this compile: the stored context (agents'
        edit_context edits included) plus the registry's recursive projection for everything the
        context and the *source* name — so a function that uses `self` of some class never carries
        its own declaration, and whatever it references comes along."""
        meta = json.loads(fn["meta"] or "{}") if fn is not None else {}
        if fn is not None and function_mode(fn) != "decompile":
            raise NetworkError(f"{fn['name']} is mode={function_mode(fn)}: it has no body target. "
                               f"Edit its signature/class, or set_mode(decompile) first.")
        guessed = "c++" if compilers.guess_language(header) == "c++" else "c"
        language = "c++" if (meta.get("language") == "c++" or guessed == "c++") else "c"
        header = self._render_header(fn, proj, header, source, language=language, raw_header=raw_header)
        fn_flags = meta.get("build_flags") if isinstance(meta.get("build_flags"), list) else None
        compiler = compilers.resolve(self.net, proj["slug"], language,
                                     unit=(fn["unit"] if fn is not None else None),
                                     cu=(meta.get("cu") if fn is not None else None),
                                     fn_flags=fn_flags)
        cfg = CompilerConfig(cmd=compiler.template(), timeout=DOCKER_TIMEOUT if compiler.sandbox == "docker" else 60,
                             sandbox=compiler.sandbox, image=compiler.image, platform=compiler.platform)
        res = compile_source(cfg, header, self._self_declared(fn, source, header),
                             source_name=compiler.source_name)
        if not res.ok and not raw_header and source.strip() and self._header_error(res.log):
            minimal = self._source_header(fn, proj, source, language)
            if minimal:
                retry = compile_source(cfg, minimal, self._self_declared(fn, source, minimal),
                                       source_name=compiler.source_name)
                if retry.ok:
                    res = retry
                    if fn is not None:
                        self._header_fallbacks[(proj["id"], fn["id"])] = minimal
        project_cfg = self.net.cfg(proj)
        fmt = str(project_cfg.get("format") or "elf").lower()
        arch = str(project_cfg.get("arch") or "x86_64")
        wrong = res.ok and res.obj and (
            (fmt == "elf" and res.obj[:4] != b"\x7fELF")
            or (fmt == "pe" and int.from_bytes(res.obj[:2], "little") not in (0x8664, 0xAA64)))
        if wrong:
            triple = compilers._triple(fmt, arch)
            hint = f"`clang --target={triple}`" if triple else "a compiler for this format"
            return CompileResult(False, None,
                                 f"the driver produced {_object_kind(res.obj)}, but this project is "
                                 f"{fmt.upper()} {arch}. Set the driver on the Plan tab (compiler.command), "
                                 f"for example {hint} (or `zig cc -target {arch}-linux-gnu`).")
        if res.ok and res.obj and fmt == "elf":
            # right container, wrong architecture: an arm64 image on an arm Mac emits aarch64 objects
            # for an x86_64 project — the diff would be nonsense, so it stops here with the fix.
            machine = int.from_bytes(res.obj[18:20], "little")
            want = {"x86_64": 0x3E, "aarch64": 0xB7}.get(arch)
            if want and machine != want:
                produced = {0x3E: "x86_64", 0xB7: "aarch64"}.get(machine, f"machine 0x{machine:X}")
                fix = (f"the image is pulled for the host's architecture — press “Pull the image” on the "
                       f"Plan tab to fetch {compiler.platform} for the target"
                       if compiler.image else f"use a driver that targets {arch}")
                return CompileResult(False, None,
                                     f"the driver produced an ELF for {produced}, but this project is "
                                     f"{fmt.upper()} {arch}: {fix}.")
        return res

    def target_obj(self, fn, proj):
        rc = self.reconstructor(proj)
        if rc is None:
            return None
        meta = json.loads(fn["meta"] or "{}")
        return rc.view({"ea": fn["vram"], "size": fn["size"], "name": meta.get("symbol") or fn["name"]})

    def tls_offsets(self, proj) -> dict[str, int]:
        """The binary's TLS variables by leaf name -> offset in the TLS block. A relocatable object
        can only spell these as SECREL + symbol; judge.compare uses this map to prove that a
        candidate TLS reloc names the same variable the binary's linked immediate names."""
        cache = getattr(self, "_tls_offsets", None)
        if cache is None:
            cache = self._tls_offsets = {}
        slug = proj["slug"]
        if slug in cache:
            return cache[slug]
        out: dict[str, int] = {}
        binary = (self.net.cfg(proj).get("binary") or {}).get("file")
        if binary:
            rng = _pe_tls_range(Path(proj["root"]) / binary)
            if rng:
                start, end = rng
                for d in (self.analysis(proj) or {}).get("data") or []:
                    ea = int(d.get("ea") or 0)
                    if start <= ea < end:
                        leaf = scoring.symbol_leaf(str(d.get("name") or ""))
                        if leaf:
                            out[leaf] = ea - start
        cache[slug] = out
        return out

    def judge(self, fn, proj, obj):
        """(candidate, Verdict, problems) for a compiled object. The Verdict carries the normalized diff
        (link-layer spellings adopted from the candidate) and the gist; evaluate() wraps it as a bool."""
        meta = json.loads(fn["meta"] or "{}")
        reader = plat_pack(self.net.cfg(proj).get("format") or "elf").object_reader()
        candidate = None
        for name in (meta.get("linkage"), meta.get("symbol"), fn["name"]):
            if name:
                try:
                    candidate = reader.extract_function(obj, name)
                except Exception as e:
                    return None, None, [f"THE COMPILED OBJECT IS NOT READABLE ({e}) — the compiler wrote a "
                                        f"malformed object; this is a toolchain failure, not your source. Retry."]
                if candidate is not None:
                    break
        if candidate is None:
            wanted = meta.get("linkage")
            if wanted:
                return None, None, [f"the object does not define `{wanted}` — the declaration mangles "
                                    f"differently (namespace, template arity, const/static, or an opaque stub); "
                                    f"fix the declaration, not the body"]
            return None, None, []
        target = self.target_obj(fn, proj)
        if target is None:
            return candidate, None, []
        rc = self.reconstructor(proj)
        read_at = ((lambda ea, n: formats.read_bytes(rc.data, rc.image, ea, n))
                   if rc is not None else None)
        verdict = judge.compare(target, candidate, tls_offsets=self.tls_offsets(proj),
                                signature=meta.get("demangled") or fn["name"],
                                symbols=self.symbol_table(proj), read_bytes=read_at)
        problems = list(verdict.problems)
        if verdict.renamed:
            problems.append("references read differently (often fine, names normalize): "
                            + ", ".join(f"{a} vs {b}" for a, b in verdict.renamed[:6]))
        if verdict.link_layer:
            problems.append("link-layer (not a difference): " + "; ".join(verdict.link_layer))
        return candidate, verdict, problems

    def evaluate(self, fn, proj, obj):
        """(candidate, verdict, problems): find the compiled function by its linkage name, judge it."""
        candidate, verdict, problems = self.judge(fn, proj, obj)
        return candidate, (verdict.match if verdict is not None else None), problems

    def extra_brief(self, fn, proj) -> list[str]:
        meta = json.loads(fn["meta"] or "{}")
        units = self.net._unit_contexts(proj["id"])
        header = self.net._context(proj["id"], self.net._effective_unit(fn, units))["header"]
        guessed = "c++" if compilers.guess_language(header) == "c++" else "c"
        language = "c++" if (meta.get("language") == "c++" or guessed == "c++") else "c"
        lines = ["", "### Where it lives",
                 f"address 0x{(fn['vram'] or 0):08X}, {fn['size']} bytes, named from {meta.get('provenance') or '?'}"
                 + (f", declared at line {meta['line']}" if meta.get("line") else "")]
        if meta.get("signature"):
            lines.append(f"signature: {meta['signature']}")
        if language == "c++":
            lines.append("language: C++ (define it as C++ so its symbol mangles the same way"
                         + (f"; the mangled name is {meta['linkage']}" if meta.get("linkage") else "") + ")")
        try:
            c = compilers.resolve(self.net, proj["slug"], language if language in ("c", "c++") else "c",
                                  unit=fn["unit"], cu=meta.get("cu"),
                                  fn_flags=(meta.get("build_flags")
                                            if isinstance(meta.get("build_flags"), list) else None))
            lines.append("compiling with: " + " ".join([*c.command, *c.flags])
                         + '  (probe one function first: compile_and_diff flags="…"; adopt with set_build_flags)')
            if any(f.startswith("-fsanitize=") for f in c.flags):
                lines.append("this binary is built with AddressSanitizer: frames go through __asan_stack_malloc_N and "
                             "start with the 0x41b58ab3 magic — the frame size and the order of locals are part of "
                             "the match, so keep them exactly as the disassembly (and IDA's draft) show them")
        except NetworkError as e:
            lines.append(f"compile settings aren't usable yet: {e}")
        frames = meta.get("inline") or []
        if frames:
            lines += ["", "### Inlined into this function (from the original build)"]
            for fr in frames[:10]:
                where = f" (called from line {fr.get('call_line')})" if fr.get("call_line") else ""
                lines.append(f"- {fr.get('name') or '(unnamed)'}{where}")
        calls, called_by = self.adjacency(proj)
        mine = sorted(set(calls.get(fn["vram"]) or []))
        if mine:
            lines.append("calls: " + ", ".join(mine[:30]))
        they = sorted(set(called_by.get(fn["vram"]) or []))
        if they:
            lines.append("called by: " + ", ".join(they[:30]))
        has_types = bool((self.analysis(proj) or {}).get("types"))
        lines += ["", "### Types — search, create, edit",
                  "Whenever the assembly shows you a class, struct or enum (a vtable store, `[rdi+8]`-style "
                  "field accesses, a factory or constructor call), work on it in the registry: `search_types` "
                  "by name, namespace, or a member you spotted — if it is there, use it in your source (the "
                  "layout comes along with the name); if it is missing, `declare_type` it and add its fields "
                  "with `edit_type(set_member)` (offset and type from the assembly; `count=` for arrays); if "
                  "something you find is wrong or incomplete, fix it with `edit_type`. Several related edits? "
                  "`lock_registry`, stage them with session=…, then `unlock_registry` — one verification for "
                  "the whole batch. Every kept edit is re-checked against all matched functions and every "
                  "agent sees it on their next compile: that is how a class gets written once for the project "
                  "instead of once per function."
                  + (" This binary has no debug info: the registry starts empty and grows only from what "
                     "agents add." if not has_types else "")]
        lines += ["", "Recompile against this file's context.h (get_context with this function): it declares "
                      "everything this function calls. A submission is exactly the function — first line to "
                      "closing brace, nothing before or after it; types go to the registry above and "
                      "declarations to the header (edit_context). Matched bytes are the only judge."]
        return lines

    def refuse_extra_content(self, source: str, function: str) -> None:
        """A submission is exactly the function — first line to closing brace. Types belong in the
        registry (so every matched function compiles against one layout) and everything else is the
        projection's job: the context header declares, the body keeps its own constants."""
        from . import registry

        types = registry.type_blocks(source)
        extra = registry.extra_content(source, function)
        if not types and not extra:
            return
        lines = ["❌ a submission is exactly the function: it starts at the function's first line and",
                 "ends at its closing brace (compile_and_diff compiles it against this file's context.h)."]
        if types:
            shown = ", ".join(types[:4]) + (f" and {len(types) - 4} more" if len(types) > 4 else "")
            name = re.sub(r"^(?:class|struct|union|enum(?: class)?|typedef|using|an unnamed\s+)\s*", "", types[0])
            name = name.rstrip(" =")
            lines.append(f"  • types this source defines ({shown}) belong in the registry:")
            if re.fullmatch(r"\w+", name):
                lines.append(f"    search_types(\"{name}\") — missing? declare_type(name=\"{name}\", kind=\"struct\")")
                lines.append(f"    then edit_type(action=\"set_member\", name=\"{name}\", mtype=\"int\", at=\"0x8\") "
                             f"per field; lock_registry first to batch several edits")
            else:
                lines.append("    search_types first; then declare_type / edit_type (lock_registry to batch edits)")
        lines += [f"  • {finding}" for finding in extra]
        lines.append("Declarations (globals, externs) live in the shared header — get_context, then edit_context.")
        lines.append("Constants and tables move inside the function body (a `static const …` local is fine).")
        raise NetworkError("\n".join(lines))

    def autopilot_one(self, agent, proj, fn) -> str:
        """Try the IDA draft as-is for one function: match | far | fail (the autopilot's books)."""
        self.ensure_seed(fn, proj)
        seed = self.net.store.one("SELECT seed FROM functions WHERE id=?", fn["id"])["seed"]
        if not seed:
            return "fail"
        source = "/* IDA decompilation (Hex-Rays), tried by autopilot */\n" + seed
        try:
            res = self.net.attempt(agent, fn["name"], source, proj["slug"])
        except NetworkError:
            return "fail"
        if res["matched"]:
            return "match"
        return "far" if res["score"] is not None else "fail"

    # ------------------------------------------------------------------ IDA seeds

    def ensure_seed(self, fn, proj) -> None:
        """Fetch the Hex-Rays draft for one function once, cache it in the row ("" = none)."""
        if fn["seed"] is not None or fn["vram"] is None:
            return
        slug = proj["slug"]
        cfg = self.net.cfg(proj)
        root = Path(proj["root"])
        cache_dir = root / ".decomp-wtf" / "native"
        seed = None
        cached = ida_export.pseudocode_cached(cache_dir, [fn["vram"]])
        if cached is not None:
            seed = cached.get(fn["vram"])
        elif (cfg.get("analysis") or {}).get("ida") and ida.available():
            # seeds come from IDA; only fetch when this project's analysis actually ran through it
            source = analyze_mod.ida_source(root, cfg)
            try:
                with self._ida_lock:
                    session = self._ida_session(slug, source)
                    if session is not None:
                        found = ida_export.pseudocode_batch(session, cache_dir, [fn["vram"]])
                        seed = (found or {}).get(fn["vram"])
            except (IdaError, OSError, NetworkError):
                self._close_ida()  # the worker died (or the DB is held elsewhere): the next seed call starts a fresh one
        with self.net.store.tx() as db:
            db.execute("UPDATE functions SET seed=? WHERE id=?", (seed or "", fn["id"]))

    # ---------------------------------------------------------------- the database writes
    #
    # The .i64 is the database: registry commits and renames land *in IDA*, not only in
    # registry.json. Saves are debounced (2.2 GB takes seconds to write); the commit path
    # forces one per batch and _close_ida flushes whatever is still dirty.

    def ida_ready(self) -> bool:
        """Whether writes can reach an IDA database at all (the backend exists and is usable)."""
        return bool(ida.available())

    def _ida_write(self, slug: str, code: str, timeout: float = 300) -> dict:
        """Run one write script through the project's long-lived session; mark the database dirty."""
        proj = self.net._project(slug)
        if proj is None:
            return {"ok": False, "error": "no project"}
        cfg = self.net.cfg(proj)
        root = Path(proj["root"])
        source = analyze_mod.ida_source(root, cfg)
        with self._ida_lock:
            session = self._ida_session(slug, source)
            if session is None:
                return {"ok": False, "error": "no IDA session"}
            res = ida.execute_python(session, code, timeout=timeout)
        self._ida_dirty = time.time()
        return {"ok": True, "res": res}

    @staticmethod
    def _write_marker(res: dict) -> dict | None:
        for line in ((res.get("res") or {}).get("stdout") or "").splitlines():
            if line.startswith("DECOMP_WRITE "):
                try:
                    return json.loads(line[len("DECOMP_WRITE "):])
                except ValueError:
                    return None
        return None

    def ida_apply_decls(self, slug: str, decls: str) -> dict:
        """C declarations into the database's local type library (registry commits land here)."""
        if not (decls or "").strip():
            return {"ok": True, "rc": 0}
        code = ("import json\n"
                f"decls = {decls!r}\n"
                "rc = db.types.parse_declarations(None, decls)\n"
                "print('DECOMP_WRITE ' + json.dumps({'rc': int(rc)}))\n")
        res = self._ida_write(slug, code)
        if not res.get("ok"):
            return res
        marker = self._write_marker(res)
        return {"ok": True, "rc": (marker or {}).get("rc", 0)}

    def ida_rename(self, slug: str, ea: int, name: str) -> bool:
        """Rename one address in the database (the name agents give a function persists there)."""
        code = ("import ida_name, json\n"
                f"ok = ida_name.set_name({int(ea)}, {name!r}, ida_name.SN_NOWARN | ida_name.SN_FORCE)\n"
                "print('DECOMP_WRITE ' + json.dumps({'ok': bool(ok)}))\n")
        res = self._ida_write(slug, code)
        if not res.get("ok"):
            return False
        return bool((self._write_marker(res) or {}).get("ok"))

    def ida_save(self, slug: str, *, force: bool = False, quiet: float = 60.0) -> bool:
        """Write the database to disk when there are pending writes. Without `force` a save only
        happens once the database has been quiet for `quiet` seconds (debounce: the .i64 is 2.2 GB
        on ORION and a save takes real time)."""
        if self._ida_dirty is None or self._ida is None:
            return False
        if not force and time.time() - self._ida_dirty < quiet:
            return False
        session = self._ida[1]
        # idalib's save_database returns None (not False) on success; reaching the print is the
        # success signal, and a script failure raises before it
        res = ida.execute_python(session, "import idaapi, json\n"
                                          "idaapi.save_database('')\n"
                                          "print('DECOMP_WRITE ' + json.dumps({'ok': True}))\n",
                                 timeout=900)
        self._ida_dirty = None
        return bool((self._write_marker({"res": res}) or {}).get("ok"))

    def ida_read(self, slug: str, code: str, *, timeout: float = 180) -> dict:
        """Run one READ-ONLY IDAPython snippet through the project's long-lived session: the read
        twin of the registry write path, and it never marks the database dirty."""
        proj = self.net._project(slug)
        if proj is None:
            raise NetworkError("no project")
        cfg = self.net.cfg(proj)
        source = analyze_mod.ida_source(Path(proj["root"]), cfg)
        with self._ida_lock:
            session = self._ida_session(slug, source)
            if session is None:
                raise NetworkError("the IDA session isn't available")
            return ida.execute_python(session, code, timeout=timeout)

    def ida_lookup(self, slug: str, action: str, query: str = "", count: int = 40, *,
                   timeout: float = 180) -> str:
        """The curated read-only IDA surface for agents (xrefs, disasm, decompile, types, globals,
        strings, segments). Answers are cached by the database's identity: Hex-Rays and the big
        Names() scans are paid once per query per database state."""
        proj = self.net._project(slug)
        if proj is None:
            raise NetworkError("no project")
        cfg = self.net.cfg(proj)
        root = Path(proj["root"])
        source = analyze_mod.ida_source(root, cfg)
        key = ida_export.db_key(source) if source.exists() else "nosource"
        digest = hashlib.sha1(f"{action}|{query}|{count}".encode()).hexdigest()[:16]
        cache = root / ".decomp-wtf" / "ida-cache" / key / f"{action}-{digest}.json"
        if cache.exists():
            try:
                return ida_queries.render(action, json.loads(cache.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                pass  # a torn cache is a miss; the lookup below rewrites it
        res = self.ida_read(slug, ida_queries.build(action, query, count), timeout=timeout)
        payload = ida_queries.result("\n".join([res.get("stdout") or "", res.get("stderr") or ""]))
        if payload is None:
            tail = ((res.get("stdout") or "") + (res.get("stderr") or "")).strip()[-400:]
            raise NetworkError(f"IDA's {action} lookup didn't answer" + (f": {tail}" if tail else ""))
        if payload.get("error"):
            raise NetworkError(f"IDA: {payload['error']}")
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(payload), encoding="utf-8")
        return ida_queries.render(action, payload)

    def close(self) -> None:
        """Release the persistent IDA worker (the app calls this when it stops)."""
        with self._ida_lock:
            self._close_ida()

    def forget(self, slug: str) -> None:
        """Dropping a project releases its IDA database before the folder goes: the worker must not
        keep a deleted .i64 held, and a re-import must never meet the stale session."""
        with self._ida_lock:
            if self._ida is not None and self._ida[0][0] == slug:
                try:
                    ida.close_database(self._ida[1])
                except Exception:
                    pass
                self._close_ida()  # closing the worker is the guarantee nothing still holds the file
        self._analysis.pop(slug, None)
        self._recons.pop(slug, None)
        if self._adj_key is not None and self._adj_key[0] == slug:
            self._adj_key, self._calls, self._called_by = None, {}, {}

    def pull_image(self, slug: str, log=print) -> str:
        """Pull the project's container image **for the target's platform**. Saving the image in the
        compiler card runs this as a background job: the first compile must not pay a multi-minute
        docker pull inside its sixty-second timeout, and an arm Mac must not get the arm64 variant
        of the image when the binary is x86_64."""
        cfg = self.net.cfg(self.net._project(slug))
        image = str(((cfg.get("compiler") or {}).get("image")) or "").strip()
        if not image:
            return "no container image configured"
        if not shutil.which("docker"):
            raise NetworkError(f"this project compiles in {image!r}, but docker isn't on PATH")
        platform = compilers.docker_platform(str(cfg.get("format") or "elf"), str(cfg.get("arch") or "x86_64"))
        ready = f"{image} is already pulled" + (f" for {platform}" if platform else "")
        if compilers.image_present(image, platform):
            log(ready)
            return ready
        cmd = ["docker", "pull", *(["--platform", platform] if platform else []), image]
        log(f"pulling {image}" + (f" for {platform} — the target's architecture, not this Mac's" if platform
                                  else " — first time only, this can take a while"))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
        tail: list[str] = []
        for line in proc.stdout or ():
            line = line.rstrip()
            if line:
                tail.append(line)
                log(f"  {line}")
        if proc.wait() != 0:
            raise NetworkError(f"docker pull {image} failed: {tail[-1] if tail else 'no output'}")
        log(f"{image} ready — compiles run in it from now on")
        return f"{image} ready"

    def _ida_session(self, slug: str, binary: Path):
        if self._ida is not None and self._ida[0] == (slug, str(binary)):
            return self._ida[1]
        self._close_ida()
        session = ida.IdaSession(timeout=20, ready_timeout=5, log=lambda *_: None)  # a held DB must not stall the edit
        session.__enter__()
        try:
            ida.open_database(session, binary, timeout=10, log=lambda *_: None)
        except ida.IdaError as exc:
            session.close()
            friendly = friendly_ida_error(str(exc))
            if friendly:
                raise NetworkError(friendly) from exc
            raise
        except BaseException:
            session.close()
            raise
        self._ida = ((slug, str(binary)), session)
        return session

    def _close_ida(self) -> None:
        if self._ida is not None:
            if self._ida_dirty is not None:
                try:  # flush pending writes before the worker goes
                    self.ida_save(self._ida[0][0], force=True)
                except Exception:
                    pass
            try:
                self._ida[1].close()
            except Exception:
                pass
            self._ida = None
