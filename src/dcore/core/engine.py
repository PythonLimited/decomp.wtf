"""The local engine: native programs (ELF, PE, Mach-O) on top of the coordination core.

Network (claims, attempts, best attempts, notes, a regression-tested shared header) does the
bookkeeping several agents need to work on one codebase. A native project adds:

- targets from the binary's analysis (an ida/ghidra backend sweep plus the platform pack's debug
  info), judged by compiling the candidate with the original compiler and diffing byte for byte;
- the type registry and per-unit context headers the projections compile against;
- tools for what the loop needs: claim, compile_and_diff, get_context/edit_context, the registry.

The class here is the store-backed engine; `dcore.targets` decides what ELF or x86 even means and
`dcore.backends` supplies the enrichment. Everything stays on this computer.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import struct
import threading
import time
from pathlib import Path

from . import detect, scoring
from ..targets.objects import FunctionObj
from .network import Agent, Network, NetworkError, _hash_token, function_mode

# What this build can plan, per platform pack — the human-readable summary the Setup page shows.
# The packs answer for themselves in code; this is only what a person reads.
PLATFORM_STATUS = {"elf": "ready", "pe": "parsing and plan; judging needs COFF + msvc-wine",
                   "macho": "parsing; judging needs its object reader", "android": "as elf (NDK toolchains)"}
# Functions this small are handed out in batches (claim_function count): agents match most on the first try.
BATCH_INSNS = 48
PLATFORM_COMPILERS = {"n64": ["gcc-2.7.2-kmc", "ido-7.1", "ido-5.3"], "psx": ["gcc-2.7.2-psx", "gcc-2.8.1-psx"],
                      "ps2": ["ee-gcc-2.96"], "gba": ["agbcc"]}
_AUTO_TOKEN = re.compile(r"\b(?:func|D|B|jtbl|RO|STR|FLT|DBL)_[0-9A-F]{8}\b")
_ADDRESS = re.compile(r"^(?:0x([0-9A-Fa-f]{1,16})|([0-9A-Fa-f]{7,16}))$", re.I)

GP_NOTE = """
/* This game keeps small globals (8 bytes or less) in $gp-relative small data. Declare those here WITHOUT
 * `extern` (for example `s32 D_8001B278;`): then the compiler reads them through $gp, like the game does.
 * With `extern`, it builds the full address instead and the function can't match. */
"""

BASE_HEADER = """/* context.h for {title}: shared by every function. Agents grow it with edit_context:
 * add a prototype or struct the moment you work one out, so the next function benefits. */

typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;
typedef float f32;
typedef double f64;
typedef volatile u8 vu8;
typedef volatile u16 vu16;
typedef volatile u32 vu32;
typedef volatile s32 vs32;
typedef int s32_bool;

#define NULL ((void *)0)
#define TRUE 1
#define FALSE 0
#define ARRAY_COUNT(arr) (s32)(sizeof(arr) / sizeof(arr[0]))
"""


def _slugify(title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return slug[:40] or "rom"


def _preview(data: bytes | None, kind: str) -> str:
    if not data:
        return ""
    text = data.split(b"\0", 1)[0]
    if len(text) >= 3 and all(32 <= c < 127 or c in (9, 10) for c in text):
        return json.dumps(text.decode("ascii"))
    return data[:16].hex(" ")


class Engine(Network):
    def __init__(self, db_path: str | Path, workspace: Path, claim_ttl: int = 30 * 60):
        super().__init__(db_path, claim_ttl=claim_ttl)
        self.workspace = Path(workspace)
        self._xrefs: dict[int, dict] = {}
        self._seed_lock = threading.Lock()
        self._diffs: dict[tuple, dict] = {}  # (function, source, context, compiler) -> diff for the GUI
        self.autopilots: dict[str, dict] = {}  # slug -> progress of trying every function's machine draft
        from .native import NativeEngine  # analysis, plan, per-function judging
        self.native = NativeEngine(self)

    # ------------------------------------------------------------------ basics

    def _require_budget(self, agent: Agent) -> None:
        """Your machine, your agent: no compile budget."""

    @staticmethod
    def cfg(proj) -> dict:
        return json.loads(proj["config"])

    def project_row(self, slug: str):
        return self._project(slug)

    def native_slug(self, project: str | None) -> str | None:
        """The slug when `project` is a native program (ELF/PE), else None."""
        try:
            proj = self._project(project)
        except NetworkError:
            return None
        return proj["slug"] if self.cfg(proj).get("kind") == "native" else None

    def remove_project(self, slug: str) -> int:
        n = super().remove_project(slug)
        self.native.forget(slug)  # nothing may keep the project's IDA database open after this
        return n

    def get_function(self, function: str, project: str | None = None, agent=None) -> str:
        try:
            return super().get_function(function, project, agent)
        except NetworkError:
            # agents dereference class and member names as if they were functions: answer with the
            # layout instead of a bare "no function" (they then hand-recreate the class)
            native = self.native_slug(project) if project else None
            if native:
                hint = self.native.type_hint(native, function)
                if hint:
                    return hint
            raise

    def _function(self, name: str, project: str | None):
        """Functions can also be named by address — 0x-prefixed at any length, or the ROM-era bare
        eight digits — handy for agents reading assembly, and the way agents write names they read
        elsewhere (see _loose_functions)."""
        m = _ADDRESS.match(name.strip()) if name else None
        if m:
            proj = self._project(project)
            at = int(m.group(1) or m.group(2), 16)
            row = self.store.one("SELECT * FROM functions WHERE project_id=? AND vram=?",
                                 proj["id"], at)
            if row is not None:
                return row
            host = self.store.one("SELECT * FROM functions WHERE project_id=? AND vram<=? AND vram+size>? "
                                  "ORDER BY vram DESC LIMIT 1", proj["id"], at, at)
            if host is not None:
                raise NetworkError(f"0x{at:X} is not a function start — it sits inside "
                                   f"`{host['name']}` (starts at 0x{host['vram']:X}); use that name")
            raise NetworkError(f"no function starts at 0x{at:X} and none contains it")
        try:
            return super()._function(name, project)
        except NetworkError as e:
            rows = self._loose_functions(name, project) if name else []
            if len(rows) == 1:
                return rows[0]
            if rows:
                raise NetworkError(self._ambiguous(name, rows)) from None
            near = self._near_names(name, project) if name else []
            if near:
                raise NetworkError(f"{e}. Did you mean: {', '.join(near)}?") from None
            raise

    def _near_names(self, name: str, project: str | None, n: int = 5) -> list[str]:
        """Function names close to one that doesn't exist (a typo, another spelling of the symbol)."""
        import difflib

        try:
            proj = self._project(project)
        except NetworkError:
            return []
        sym = name.strip().strip("`'\"").split("@", 1)[0].split("(", 1)[0].strip()
        if len(sym) < 3:
            return []
        rows = self.store.all("SELECT name FROM functions WHERE project_id=? AND (name LIKE ? OR name LIKE ?) LIMIT 4000",
                              proj["id"], f"%{sym[-6:]}%", f"{sym[:4]}%")
        names = [r["name"] for r in rows]
        return difflib.get_close_matches(sym, names, n=n, cutoff=0.6) or [x for x in names if sym in x][:n]

    def _loose_functions(self, name: str, project: str | None) -> list:
        """Functions an agent may mean by a name that isn't stored as such: the plain symbol of a function whose
        name repeats across a fork's files (stored as symbol@unit), symbol@unit for one that doesn't repeat,
        Class::method, a name with its parameter list or in quotes."""
        try:
            proj = self._project(project)
        except NetworkError:
            return []
        text = name.strip().strip("`'\"").strip()
        # exact mangled or fully-qualified spellings resolve before any '@'-partition surgery:
        # mangled names are full of '@', and the disassembly hands agents exactly that spelling
        by_symbol = self.store.all(
            "SELECT * FROM functions WHERE project_id=? AND (json_extract(meta,'$.linkage')=? OR "
            "json_extract(meta,'$.demangled')=?) ORDER BY name", proj["id"], text, text)
        if not by_symbol:
            # the store's rows carry meta from import time, which predates linkage — the analysis
            # is the source of the disassembly's spelling, keyed to its ea, cached per analysis
            try:
                analysis = self.native.analysis(proj)
            except Exception:
                analysis = None
            cached = getattr(self, "_symbol_index", None)
            if analysis is not None and (cached is None or cached[0] is not analysis):
                index: dict[str, int] = {}
                for f in analysis.get("functions") or []:
                    for spelling in (f.get("linkage") or "", f.get("demangled") or ""):
                        if spelling:
                            index.setdefault(spelling, f["ea"])
                cached = (analysis, index)
                self._symbol_index = cached
            if cached is not None:
                ea = cached[1].get(text)
                if ea is not None:
                    by_symbol = self.store.all("SELECT * FROM functions WHERE project_id=? AND vram=?",
                                               proj["id"], ea)
        if by_symbol:
            return by_symbol
        sym, _, unit = text.partition("@")
        unit, _, nth = unit.partition("#")
        sym = sym.split("(", 1)[0].strip()
        if not sym:
            return []
        rows = self.store.all(
            "SELECT * FROM functions WHERE project_id=? AND (name=? OR substr(name,1,?)=? "
            "OR json_extract(meta,'$.symbol')=? OR substr(json_extract(meta,'$.demangled'),1,?)=? "
            "OR json_extract(meta,'$.demangled') LIKE ?) ORDER BY name",
            proj["id"], sym, len(sym) + 1, sym + "@", sym, len(sym) + 1, sym + "(", f"%::{sym}(%")
        if unit:
            rows = ([r for r in rows if r["unit"] == unit] or [r for r in rows if r["unit"].endswith(unit)]
                    or [r for r in rows if r["unit"].startswith(unit)] or [r for r in rows if unit in r["unit"]])
        if nth.isdigit() and len(rows) > 1:
            rows = [r for r in rows if (json.loads(r["meta"] or "{}").get("nth", 0) + 1) == int(nth)] or rows
        return [r for r in rows if r["status"] != "nosource"] or rows  # ones in files without source can't be worked on

    @staticmethod
    def _ambiguous(name: str, rows: list) -> str:
        listing = "\n".join(f"- {r['name']} ({r['status']}, {r['n_insns']} instructions)" for r in rows[:12])
        more = f"\n... and {len(rows) - 12} more" if len(rows) > 12 else ""
        return (f"{name!r} is the name of {len(rows)} functions in different files; pass the full name:\n"
                f"{listing}{more}")

    def resolve_function(self, agent: Agent | None, project: str | None, name: str) -> str:
        """The stored name for what an agent calls a function: when a plain name fits several, the one the agent
        holds a claim on."""
        try:
            return self._function(name, project)["name"]
        except NetworkError:
            rows = self._loose_functions(name, project) if name else []
            held = self.store.all("SELECT f.id, f.unit FROM claims c JOIN functions f ON f.id=c.function_id "
                                  "WHERE c.agent_id=?", agent.id) if agent else []
            if held and len(rows) > 1:  # one it holds, else the one in the file (or module) it works in
                ids, units = {h["id"] for h in held}, {h["unit"] for h in held}
                modules = {u.split("/", 1)[0] for u in units}
                for pick in ([r for r in rows if r["id"] in ids], [r for r in rows if r["unit"] in units],
                             [r for r in rows if r["unit"].split("/", 1)[0] in modules]):
                    if len(pick) == 1:
                        return pick[0]["name"]
            raise

    def _compile(self, proj, header: str, source: str, fn=None):
        if (native := self.native_slug(proj["slug"])):
            return self.native.compile_fn(fn, proj, header, source)
        return super()._compile(proj, header, source, fn=fn)

    def compile_and_diff(self, agent, function, source, project=None, flags: str = ""):
        """The canonical submission: exactly one function definition, judged against the header.

        Types belong in the registry and globals in the header; a helper that only exists to
        support this body must be folded into the body. `attempt` is the scratch/claim path and
        deliberately still allows leading helper definitions for experiments."""
        native = self.native_slug(project)
        if native:  # native submissions are exactly the function: types go to the registry, nothing else rides along
            self.native.refuse_extra_content(source, function)
        if flags:  # a flag probe: judged, never recorded — only native projects have flags at all
            if native is None:
                raise NetworkError("compiler flags are set per project here; only native programs "
                                   "probe them per attempt")
            return self.native.probe(agent, native, function, source, flags)
        return super().compile_and_diff(agent, function, source, project)

    def _evaluate(self, fn, proj, obj: bytes):
        return self.native.evaluate(fn, proj, obj)

    def _judge(self, fn, proj, obj: bytes):
        """The native judge's Verdict (normalized diff + gist), or the base fallback."""
        if self.native_slug(proj["slug"]):
            return self.native.judge(fn, proj, obj)
        return super()._judge(fn, proj, obj)

    # ------------------------------------------------------------------ import

    def import_rom(self, data: bytes | Path, *, toolchain: str | None = None, flags: list[str] | None = None,
                   confirmed: bool = False, name: str = "", ida_db: str | None = None, log=print) -> str:
        """Import a program the user owns (an ELF, PE or Mach-O file): register the project and let the
        analysis map it file by file. Returns the slug. `ida_db` hands the analysis an existing .i64/.idb."""
        if not confirmed:
            raise NetworkError("confirm that this is your own legally obtained copy of the game")
        picked = detect.identify(data, name)
        if picked.platform == "native":  # a shipped program: planned file by file, then decompiled
            origin = Path(data) if isinstance(data, (str, Path)) else None
            return self.native.create(self.workspace, picked, ida_db=ida_db, origin=origin, log=log)
    # ------------------------------------------------------------------ drafts

    def get_context(self, project: str | None, function: str | None = None) -> str:
        return super().get_context(project, function)

    def _brief(self, fn, agent, header):
        proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        if fn["status"] != "matched" and not fn["best_source"] and fn["seed"] is None:
            self.native.ensure_seed(fn, proj)  # the IDA draft, fetched once
            fn = self._function(fn["name"], proj["slug"])
        return super()._brief(fn, agent, header)

    def _seed_intro(self, fn, proj) -> str:
        if self.native_slug(proj["slug"]):
            return ("### IDA decompilation (Hex-Rays): a starting point, not a match — fix the types and the "
                    "structure; the context header declares what it calls")
        return super()._seed_intro(fn, proj)

    # ------------------------------------------------------------------ cross references

    def xrefs(self, proj) -> dict:
        """calls / called_by / uses / used_by, all keyed by address (the native adjacency)."""
        if proj["id"] in self._xrefs:
            return self._xrefs[proj["id"]]
        self._xrefs[proj["id"]] = self.native.adjacency(proj)
        return self._xrefs[proj["id"]]

    def _extra_brief(self, fn, proj) -> list[str]:
        return self.native.extra_brief(fn, proj)

    # ------------------------------------------------------------------ agent tools

    def read_data(self, slug: str, what: str, length: int = 64) -> str:
        """Bytes of the imported binary at an address or a function name."""
        return self.native.read_data(slug, what, length)

    def list_functions(self, project: str | None, status: str = "open", limit: int = 40,
                       query: str = "") -> str:
        proj = self._project(project)
        where = "" if status == "all" else " AND f.status=?"
        args: list = [proj["id"]] + ([] if status == "all" else [status])
        if status == "open":
            where += " AND f.mode='decompile'"
        q = (query or "").strip()
        if q:  # find by name fragment or by address, not just "the next ones in order"
            m = _ADDRESS.match(q)
            if m:
                where += " AND f.vram=?"
                args.append(int(m.group(1), 16))
            else:
                where += " AND f.name LIKE ?"
                args.append(f"%{q}%")
        rows = self.store.all(
            f"SELECT f.name, f.vram, f.n_insns, f.status, f.best_score, f.meta, a.name AS claimed_by FROM functions f "
            f"LEFT JOIN claims c ON c.function_id=f.id LEFT JOIN agents a ON a.id=c.agent_id "
            f"WHERE f.project_id=?{where} ORDER BY f.vram LIMIT ?", *args, limit)
        if status == "open":
            rows = [r for r in rows if function_mode(r) == "decompile"]
        if not rows:
            return f"No {status} functions" + (f" matching `{q}`" if q else "") + "."
        return "\n".join(f"- {r['name']} @0x{r['vram']:08X}: {r['n_insns']} insns, {r['status']}"
                         + (f", {function_mode(r)}" if function_mode(r) != "decompile" else "")
                         + (f", best score {r['best_score']}" if r["best_score"] is not None else "")
                         + (f", claimed by {r['claimed_by']}" if r["claimed_by"] else "") for r in rows)

    # ------------------------------------------------------------------ rooms (see collab.py)

    def claim(self, agent: Agent, project: str | None = None, function: str | None = None, strategy: str = "easiest") -> str:
        return super().claim(agent, project, function, strategy)

    def claim_many(self, agent: Agent, project: str | None, count: int, strategy: str = "easiest") -> str:
        """Several small functions at once (count 2-6): the next one by `strategy` and, when it's small, its
        neighbours in the same file. Most small functions match on the first try, so an agent writes them all and
        judges them in one compile_and_diff: a fraction of the turns. Big functions come alone."""
        count = max(1, min(int(count or 1), 6))
        if count == 1:
            return self.claim(agent, project, None, strategy)
        proj = self._project(project)
        held = self.store.all("SELECT f.* FROM claims c JOIN functions f ON f.id=c.function_id WHERE c.agent_id=? "
                              "AND f.project_id=? ORDER BY f.vram, f.id", agent.id, proj["id"])
        if not held:
            text = self.claim(agent, project, None, strategy)  # the first, the usual way (with its "nothing left")
            held = self.store.all("SELECT f.* FROM claims c JOIN functions f ON f.id=c.function_id WHERE c.agent_id=? "
                                  "AND f.project_id=?", agent.id, proj["id"])
            if not held or held[0]["n_insns"] > BATCH_INSNS:
                return text
        first = held[0]
        rows = list(held)
        if first["n_insns"] <= BATCH_INSNS and len(rows) < count:
            rows += self._batch_more(agent, proj, first, count - len(rows))
        if len(rows) == 1:
            return self.claim(agent, project, None, strategy)
        names = [r["name"] for r in rows]
        head = (f"## CLAIMED {len(rows)} small functions: {', '.join(names)}\n"
                f"Write all of them, then judge them in one call: compile_and_diff(function=\"{', '.join(names)}\", "
                f"source=<all {len(rows)} definitions>). Each is judged on its own and saved as soon as it matches; "
                "then fix what's left (one at a time is fine). release_function any you can't do.")
        briefs = [self._brief(r, agent, "CLAIMED") for r in rows]
        return "\n\n---\n\n".join([head, *briefs])

    def _batch_more(self, agent: Agent, proj, first, n: int) -> list:
        """Up to n more small open functions next to `first` (same file, nearest address), claimed for the agent."""
        now = time.time()
        with self.store.tx() as db:
            self._expire_claims(db)
            rows = db.execute(
                "SELECT f.* FROM functions f WHERE f.project_id=? AND f.status='open' AND f.mode='decompile' "
                "AND f.boost >= 0 AND f.n_insns <= ? "
                "AND f.abandons = 0 AND f.unit=? AND f.id NOT IN (SELECT function_id FROM claims) "
                "ORDER BY ABS(COALESCE(f.vram, 0) - ?), f.id LIMIT ?",
                (proj["id"], BATCH_INSNS, first["unit"], first["vram"] or 0, n)).fetchall()
            rows = [r for r in rows if function_mode(r) == "decompile"]
            for r in rows:
                db.execute("INSERT INTO claims VALUES(?,?,?,?)", (r["id"], agent.id, now, now + self.claim_ttl))
                self._event(db, proj["id"], agent.id, "claim", r["name"])
        return rows

    def attempt_many(self, agent: Agent, names: list[str], source: str, project: str | None = None) -> str:
        """compile_and_diff for several functions in one source: each judged on its own, in order."""
        out, matched = [], 0
        for name in names:
            try:
                res = self.attempt(agent, name, source, project)
            except NetworkError as e:
                res = {"text": f"❌ {e}", "matched": False}
            matched += bool(res.get("matched"))
            out.append(f"### {name}\n{res['text']}")
        return f"{matched} of {len(names)} matched.\n\n" + "\n\n".join(out)

    def _yield_autopilot(self, function: str | None, project: str | None) -> None:
        """The autopilot holds a function only while its draft compiles: an agent that wants it waits for that."""
        if not function:
            return
        try:
            fid = self._function(function, project)["id"]
        except NetworkError:
            return
        for _ in range(100):
            held = self.store.one("SELECT a.name FROM claims c JOIN agents a ON a.id=c.agent_id WHERE c.function_id=?", fid)
            if not held or held["name"] != "autopilot":
                return
            time.sleep(0.2)

    def attempt(self, agent: Agent, function: str, source: str, project: str | None = None) -> dict:
        """Scratch/claim path: compile and record, allowing leading local helpers for experiments.

        Final submissions go through `compile_and_diff`, which enforces the function-only fence;
        a match recorded here still means the target function's bytes are identical."""
        self._yield_autopilot(function, project)
        return super().attempt(agent, function, source, project)

    def release(self, agent: Agent, function: str, notes: str, project: str | None = None) -> str:
        return super().release(agent, function, notes, project)

    def add_note(self, agent: Agent, project: str | None, text: str, function: str | None = None) -> str:
        return super().add_note(agent, project, text, function)

    # ------------------------------------------------------------------ export

    def export_project(self, slug: str, log=print) -> dict:
        """Write a reconstructable source tree and prove it rebuilds the program: every matched function
        is re-judged in the form it will live in (see core/export.py)."""
        proj = self._project(slug)
        from .export import export_native

        res = export_native(self, slug, Path(proj["root"]) / "source", log=log)
        with self.store.tx() as db:  # shown on the project page: what's in the tree and whether it rebuilds
            cfg = json.loads(db.execute("SELECT config FROM projects WHERE id=?", (proj["id"],)).fetchone()["config"])
            cfg["export"] = {"t": time.time(), "path": str(res["path"]), "identical": res.get("identical"),
                             "matched": res.get("matched"), "functions": res.get("functions"),
                             "fallback": len(res.get("fallback") or [])}
            db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))
        return res

    # ------------------------------------------------------------------ for the GUI

    def overview(self, slug: str) -> dict:
        proj = self._project(slug)
        last = self.store.one("SELECT MAX(created_at) AS t FROM events WHERE project_id=?", proj["id"])["t"]
        cfg = self.cfg(proj)
        # matches by the helper agents the app runs (their spend is what `spend` counts)
        helpers = self.store.one(
            "SELECT COUNT(*) AS n FROM functions f JOIN agents a ON a.id=f.matched_agent_id WHERE f.project_id=? "
            "AND f.status='matched' AND a.origin='local' AND a.name NOT IN ('you','autopilot')", proj["id"])["n"]
        return self._overview(slug, proj) | {"last_activity": last, "autopilot": self.autopilot_status(slug),
                                             "helper_matches": helpers,
                                             "spend": cfg.get("spend"), "instructions": cfg.get("instructions") or "",
                                             "priority": cfg.get("priority", [])}

    def _overview(self, slug: str, proj) -> dict:
        return self.native.overview(slug)

    def function_map(self, slug: str) -> list[dict]:
        proj = self._project(slug)
        # interface/excluded rows are off-plan and stay out; library/import rows are listed (the
        # function list has a Library filter) but never counted as work
        rows = self.store.all(
            "SELECT f.name, f.vram, f.size, f.n_insns, f.status, f.best_score, f.attempts, f.unit, f.matched_at, "
            "a.name AS agent, m.name AS matched_by FROM functions f LEFT JOIN claims c ON c.function_id=f.id "
            "LEFT JOIN agents a ON a.id=c.agent_id LEFT JOIN agents m ON m.id=f.matched_agent_id "
            "WHERE f.project_id=? AND f.status NOT IN ('interface','excluded') "
            "ORDER BY f.vram, f.unit, f.id",
            proj["id"])
        return [{"name": r["name"], "vram": r["vram"], "size": r["size"], "insns": r["n_insns"], "unit": r["unit"],
                 "status": r["status"] if r["status"] in ("matched", "asm", "library") else "working" if r["agent"] else "open",
                 "best": r["best_score"], "attempts": r["attempts"], "agent": r["agent"],
                 "matched_at": r["matched_at"], "matched_by": r["matched_by"]} for r in rows]

    def map_signature(self, slug: str) -> str:
        """What the function map shows, summed up: it changes when a function is added, matched, tried or claimed.
        A few sums over indexed rows, so the GUI can ask "anything new?" every few seconds without fetching tens of
        thousands of functions (renames and splits come with events, which refetch anyway)."""
        proj = self._project(slug)
        f = self.store.one("SELECT COUNT(*) AS n, COALESCE(MAX(id), 0) AS hi, COALESCE(SUM(attempts), 0) AS at, "
                           "COALESCE(SUM(status='matched'), 0) AS m, COALESCE(SUM(best_score), 0) AS bs, "
                           "COALESCE(MAX(matched_at), 0) AS ma FROM functions WHERE project_id=?", proj["id"])
        c = self.store.one("SELECT COUNT(*) AS n, COALESCE(SUM(c.function_id * 31 + c.agent_id), 0) AS k FROM claims c "
                           "JOIN functions f ON f.id=c.function_id WHERE f.project_id=?", proj["id"])
        return f"{f['n']}.{f['hi']}.{f['at']}.{f['m']}.{f['bs']}.{f['ma']}.{c['n']}.{c['k']}"

    # ------------------------------------------------------------------ what agents spend, and steering them

    def _update_cfg(self, slug: str, change) -> dict:
        """Change a project's config in one transaction (change(cfg) edits it in place)."""
        proj = self._project(slug)
        with self.store.tx() as db:
            cfg = json.loads(db.execute("SELECT config FROM projects WHERE id=?", (proj["id"],)).fetchone()["config"])
            change(cfg)
            db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))
        return cfg

    def add_spend(self, slug: str, usd: float, tokens: int) -> None:
        if usd or tokens:
            def change(cfg):
                sp = cfg.setdefault("spend", {"usd": 0.0, "tokens": 0})
                sp["usd"] = round(sp.get("usd", 0) + usd, 6)
                sp["tokens"] = sp.get("tokens", 0) + tokens
            self._update_cfg(slug, change)

    def spend(self, slug: str) -> dict | None:
        return self.cfg(self._project(slug)).get("spend")

    def set_instructions(self, slug: str, text: str) -> None:
        """What the user wants agents to know or focus on, given to every agent on this project."""
        self._update_cfg(slug, lambda cfg: cfg.__setitem__("instructions", text.strip()[:4000]))

    def instructions(self, slug: str) -> str:
        return self.cfg(self._project(slug)).get("instructions") or ""

    def set_priority(self, slug: str, name: str, on: bool = True) -> list[str]:
        """Functions the user wants done next: automatic claims take these first."""
        fn = self._function(name, slug)

        def change(cfg):
            items = [n for n in cfg.get("priority", []) if n != fn["name"]]
            cfg["priority"] = ([fn["name"]] + items) if on else items
        return self._update_cfg(slug, change)["priority"]

    def claim_row(self, agent: Agent, project: str | None = None, function: str | None = None, strategy: str = "easiest"):
        if function is None and project:
            proj = self._project(project)
            for name in self.cfg(proj).get("priority", []):
                row = self.store.one("SELECT f.id, f.status FROM functions f WHERE f.project_id=? AND f.name=?", proj["id"], name)
                held = self.store.one("SELECT 1 FROM claims WHERE agent_id=?", agent.id)
                if row and row["status"] == "open" and not held and not self.store.one(
                        "SELECT 1 FROM claims WHERE function_id=?", row["id"]):
                    function = name
                    break
        self._yield_autopilot(function, project)
        return Network.claim_row(self, agent, project, function, strategy)

    # ------------------------------------------------------------------ autopilot

    def start_autopilot(self, slug: str, workers: int = 3) -> dict:
        """Try every open function's Hex-Rays draft through the judge, smallest first, in the background.
        Whatever already matches is saved before any agent spends a token on it; drafts that compile become
        the function's best attempt, so agents start from them. Agents and autopilot never collide: a
        function is held only while its draft compiles, and claimed ones are skipped."""
        state = self.autopilots.get(slug)
        if state and state["state"] == "running":
            return state
        try:
            proj = self._project(slug)
            if not (self.cfg(proj).get("analysis") or {}).get("ida"):
                raise NetworkError("the autopilot tries each function's IDA (Hex-Rays) draft: analyze this "
                                   "binary through IDA first")
            ids = [r["id"] for r in self.store.all("SELECT id FROM functions WHERE project_id=? AND status='open' "
                                                   "AND mode='decompile' ORDER BY n_insns, vram", proj["id"])]
            try_one = self._autopilot_one
            no_drafts = ""
        except NetworkError as e:
            ids, try_one, no_drafts = [], None, str(e)
        state = {"state": "running", "total": len(ids), "tried": 0, "matched": 0, "near": 0,
                 "phase": "drafts", "no_drafts": no_drafts, "started_at": time.time(), "stop": threading.Event()}
        self.autopilots[slug] = state
        threading.Thread(target=self._autopilot_run, args=(slug, ids, state, workers, try_one),
                         daemon=True, name=f"autopilot-{slug}").start()
        return state

    def stop_autopilot(self, slug: str) -> None:
        if (state := self.autopilots.get(slug)) and state["state"] == "running":
            state["stop"].set()

    def autopilot_status(self, slug: str) -> dict | None:
        state = self.autopilots.get(slug)
        if state:
            return {k: v for k, v in state.items() if k != "stop"}
        last = self.cfg(self._project(slug)).get("autopilot")  # the last run, from before the app restarted
        return {"state": "done", **last} if last else None

    def _autopilot_run(self, slug: str, ids: list[int], state: dict, workers: int, try_one=None) -> None:
        from concurrent.futures import ThreadPoolExecutor

        agent, _ = self.local_agent("autopilot")
        proj = self._project(slug)
        try_one = try_one or self._autopilot_one
        state["phase"] = "drafts"
        ids = [fid for fid in ids if (r := self.store.one("SELECT status FROM functions WHERE id=?", fid)) and r["status"] == "open"]
        state["total"] = len(ids)

        def one(fid: int) -> None:
            if state["stop"].is_set():
                return
            try:
                outcome = try_one(agent, proj, fid)
            except Exception:  # one odd function must not stop the rest
                outcome = "fail"
            state["tried"] += 1
            if outcome in ("match", "near"):
                state[{"match": "matched", "near": "near"}[outcome]] += 1

        try:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(one, ids))
        finally:
            state["state"] = "stopped" if state["stop"].is_set() else "done"
            state["finished_at"] = time.time()
            with self.store.tx() as db:
                cfg = json.loads(db.execute("SELECT config FROM projects WHERE id=?", (proj["id"],)).fetchone()["config"])
                cfg["autopilot"] = {k: state.get(k) for k in ("total", "tried", "matched", "near", "started_at",
                                                              "finished_at")}
                db.execute("UPDATE projects SET config=? WHERE id=?", (json.dumps(cfg), proj["id"]))
            if state["matched"]:
                with self.store.tx() as db:
                    self._event(db, proj["id"], agent.id, "autopilot",
                                f"{state['matched']} of {state['tried']} functions matched from machine drafts")

    def on_match(self, proj, function_id: int, agent: Agent | None = None) -> None:
        """Its twins get its code, at once. (Not for the full twins pass's own matches while it runs: it tries
        those twins itself.)"""
        if proj is None:
            return
        if agent is not None and agent.name == "autopilot" and self.twins._full_running(proj["slug"]):
            return
        self.twins.after_match(proj, function_id)

    def try_quietly(self, agent, proj, fn, source: str) -> dict:
        """Judge one candidate for a function nobody holds (autopilot's tries): held only while it compiles,
        recorded as an attempt like any other. {"matched", "score"}."""
        now = time.time()
        with self.store.tx() as db:
            self._expire_claims(db)
            if db.execute("SELECT 1 FROM claims WHERE function_id=?", (fn["id"],)).fetchone():
                raise NetworkError(f"{fn['name']} is claimed")
            db.execute("INSERT INTO claims VALUES(?,?,?,?)", (fn["id"], agent.id, now, now + 300))
        try:
            ctx = self._context(proj["id"], fn["unit"])
            result = self._compile(proj, ctx["header"], source)
            if not result.ok:
                return {"matched": False, "score": None}
            cand, verdict, _ = self._evaluate(fn, proj, result.obj)
            if cand is None:
                return {"matched": False, "score": None}
            d = scoring.diff(self._target_obj(fn, proj), cand)
            if verdict is not None:
                d = scoring.DiffResult(0 if verdict else max(1, d.score), d.max_score, d.rows, verdict)
            self._record(fn, agent, d.score, source, ctx["version"], matched=d.bytes_match)
            return {"matched": d.bytes_match, "score": d.score}
        finally:
            with self.store.tx() as db:
                db.execute("DELETE FROM claims WHERE function_id=? AND agent_id=?", (fn["id"], agent.id))

    def _autopilot_one(self, agent, proj, fid: int) -> str:
        """match | near | far | fail | skip, for one function's draft."""
        now = time.time()
        with self.store.tx() as db:
            self._expire_claims(db)
            fn = db.execute("SELECT * FROM functions WHERE id=?", (fid,)).fetchone()
            if fn is None or fn["status"] != "open" or db.execute("SELECT 1 FROM claims WHERE function_id=?", (fid,)).fetchone():
                return "skip"
            db.execute("INSERT INTO claims VALUES(?,?,?,?)", (fid, agent.id, now, now + 300))
        try:
            if self.native_slug(proj["slug"]):
                return self.native.autopilot_one(agent, proj, fn)  # tries the IDA draft as-is
            self._seed_for(fn, proj)  # the readable draft, for the agents that come after
            ctx = self._context(proj["id"], fn["unit"])
            asm = self._asm_text(fn, proj)
            data_asm = "\n".join(self._jtbl_asm(proj, fn)) if "jtbl_" in asm else None
            draft = seeds.generate_from_asm(asm, fn["name"], self.cfg(proj)["compiler"]["toolchain"],
                                            ctx["header"], data_asm, valid=True)
            if not draft:
                return "fail"
            source = f"/* machine draft (m2c), tried by autopilot */\n{seeds.M2C_MACROS}\n{draft}\n"
            result = self._compile(proj, ctx["header"], source)
            if not result.ok:
                return "fail"
            cand, verdict, _ = self._evaluate(fn, proj, result.obj)
            if cand is None:
                return "fail"
            d = scoring.diff(self._target_obj(fn, proj), cand)
            if verdict is not None:
                d = scoring.DiffResult(0 if verdict else max(1, d.score), d.max_score, d.rows, verdict)
            self._record(fn, agent, d.score, source, ctx["version"], matched=d.bytes_match)
            return "match" if d.bytes_match else "near" if d.percent >= 90 else "far"
        finally:
            with self.store.tx() as db:
                db.execute("DELETE FROM claims WHERE function_id=? AND agent_id=?", (fid, agent.id))

    def function_diff(self, slug: str, name: str, which: str = "latest") -> dict:
        """The target next to an attempt, instruction by instruction, for the GUI: the matched C, else the latest
        (or best) attempt, compiled like the judge does — with the function passed through, or the recompile
        skips the file's own flags (a matched -O2 function drew a stale 41% next to its 100%). Cached, so
        watching an agent costs nothing."""
        fn = self._function(name, slug)
        proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        latest = self.store.one("SELECT source FROM attempts WHERE function_id=? AND source IS NOT NULL "
                                "ORDER BY id DESC LIMIT 1", fn["id"])
        picks = [("matched", fn["matched_source"]), ("best", fn["best_source"]),
                 ("latest", latest["source"] if latest else None)]
        if which == "latest":
            picks = [picks[0], picks[2], picks[1]]
        kind, source = next(((k, v) for k, v in picks if v), (None, None))
        if source is None:
            return {"kind": None, "rows": None}
        ctx = self._context(proj["id"], fn["unit"])
        key = (fn["id"], hashlib.sha1(source.encode()).hexdigest(), ctx["version"], proj["config"])
        if key in self._diffs:
            return self._diffs[key] | {"kind": kind}
        result = self._compile(proj, ctx["header"], source, fn=fn)
        if not result.ok:
            out = {"rows": None, "error": result.log.strip()[-3000:] or "it didn't compile", "source": source,
                   "infra": bool(getattr(result, "infra", False))}
        else:
            cand, verdict, problems = self._judge(fn, proj, result.obj)
            if cand is None:
                bad = next((p for p in problems if p.startswith("THE COMPILED OBJECT IS NOT READABLE")), None)
                out = {"rows": None, "error": bad or f"the object has no function named `{fn['name']}`",
                       "source": source, "infra": bool(bad)}
            else:
                if verdict is not None:
                    d = verdict.diff
                    matched = verdict.match
                else:
                    d = scoring.diff(self._target_obj(fn, proj), cand)
                    matched = d.bytes_match
                d = scoring.DiffResult(0 if matched else max(1, d.score), d.max_score, d.rows, matched,
                                       gist=d.gist)
                out = {"rows": [list(r) for r in d.rows], "score": d.score,
                       "percent": 100.0 if d.bytes_match else min(99.9, int(d.percent * 10) / 10),
                       "problems": problems, "source": source, "gist": d.gist}
        if len(self._diffs) > 128:
            self._diffs.pop(next(iter(self._diffs)))
        self._diffs[key] = out
        return out | {"kind": kind}

    def function_detail(self, slug: str, name: str) -> dict:
        fn = self._function(name, slug)
        proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        attempts = self.store.all(
            "SELECT t.score, t.created_at, a.name AS agent FROM attempts t LEFT JOIN agents a ON a.id=t.agent_id "
            "WHERE t.function_id=? ORDER BY t.id", fn["id"])
        latest = self.store.one("SELECT source, score FROM attempts WHERE function_id=? AND source IS NOT NULL "
                                "ORDER BY id DESC LIMIT 1", fn["id"])
        notes = self.store.all("SELECT n.text, n.created_at, a.name AS agent FROM notes n LEFT JOIN agents a "
                               "ON a.id=n.agent_id WHERE n.function_id=? ORDER BY n.id DESC LIMIT 10", fn["id"])
        if self.native_slug(slug):
            calls_map, called_by_map = self.native.adjacency(proj)
            calls = sorted(set(calls_map.get(fn["vram"], [])))
            called_by = sorted(set(called_by_map.get(fn["vram"], [])))
            if not (fn["matched_source"] or fn["best_source"] or latest) and fn["seed"] is None:
                self.native.ensure_seed(fn, proj)
                fn = self._function(fn["name"], slug)
        else:
            x = self.xrefs(proj)
            syms = self.symbols(proj["id"])
            calls = [syms.label(a) for a in sorted(x["calls"].get(fn["vram"], ()))]
            called_by = [syms.label(a) for a in sorted(x["called_by"].get(fn["vram"], ()))]
            if not (fn["matched_source"] or fn["best_source"] or latest) and fn["seed"] is None:
                with self._seed_lock:
                    self._seed_for(fn, proj)
                fn = self._function(fn["name"], slug)
        return {
            "name": fn["name"], "vram": fn["vram"], "rom_offset": fn["rom_offset"], "size": fn["size"],
            "insns": fn["n_insns"], "status": fn["status"], "best": fn["best_score"],
            "mode": function_mode(fn),
            "signature": (json.loads(fn["meta"] or "{}").get("signature") or ""),
            "sig": (self.native.signature_info(fn, proj) if self.native_slug(slug) else None),
            "asm": self._asm_text(fn, proj),
            "source": fn["matched_source"] or fn["best_source"] or (latest["source"] if latest else None) or fn["seed"],
            "source_kind": "matched" if fn["matched_source"] else "best" if fn["best_source"] else
                           "latest" if latest else "draft" if fn["seed"] else None,
            "scores": [{"score": a["score"], "t": a["created_at"], "agent": a["agent"]} for a in attempts],
            "notes": [dict(n) for n in notes],
            "calls": calls,
            "called_by": called_by,
        }

    def generated_header(self, slug: str, name: str) -> str:
        """The exact header the function's next compile would get, rendered on demand for the
        drawer's Header tab (not on every poll)."""
        if not self.native_slug(slug):
            return ""
        return self.native.header_view(self._function(name, slug), self.project_row(slug))

    def stats(self, slug: str) -> dict:
        """Who did what and how fast: the overview's numbers (asked every few seconds, not every second)."""
        pid = self._project(slug)["id"]
        now = time.time()
        rows = self.store.all(
            "SELECT a.name AS agent, COUNT(t.id) AS compiles, MAX(t.created_at) AS last FROM attempts t "
            "JOIN functions f ON f.id=t.function_id JOIN agents a ON a.id=t.agent_id WHERE f.project_id=? GROUP BY a.id", pid)
        matched = {r["agent"]: r["n"] for r in self.store.all(
            "SELECT a.name AS agent, COUNT(*) AS n FROM functions f JOIN agents a ON a.id=f.matched_agent_id "
            "WHERE f.project_id=? AND f.status='matched' GROUP BY a.id", pid)}
        board = [{"agent": r["agent"], "compiles": r["compiles"], "matched": matched.pop(r["agent"], 0), "last": r["last"]}
                 for r in rows]
        board += [{"agent": a, "compiles": 0, "matched": n, "last": None} for a, n in matched.items()]
        board.sort(key=lambda r: (-r["matched"], -r["compiles"]))
        per_hour = [0] * 24
        for r in self.store.all("SELECT matched_at FROM functions WHERE project_id=? AND status='matched' AND matched_at > ?",
                                pid, now - 86400):
            per_hour[23 - min(23, max(0, int((now - r["matched_at"]) // 3600)))] += 1  # (one matched since `now`: this hour)
        compiles = self.store.one("SELECT COUNT(*) AS n FROM attempts t JOIN functions f ON f.id=t.function_id "
                                  "WHERE f.project_id=? AND t.created_at > ?", pid, now - 3600)["n"]
        return {"agents": board[:24], "matches_per_hour": per_hour, "compiles_last_hour": compiles}

    def validate_units(self, slug: str, report: bool = True) -> list[dict]:
        """Parse-check every unit that carries declaration entries. Entry order is semantic, so a unit
        can be wedged by entries that were valid under an older render order; surfacing that at
        startup (as a deduped report) beats an agent rediscovering it mid-session and burning six
        minutes on repairs the gate must refuse. Only header errors (context.h lines) are reported —
        a missing compiler is not a broken unit."""
        proj = self._project(slug)
        if not self.native_slug(slug):
            return []
        from . import entries as entries_mod
        from . import interfaces

        rows = self.store.all("SELECT DISTINCT unit FROM context_entries WHERE project_id=? AND removed_at IS NULL",
                              proj["id"])
        broken: list[dict] = []
        for row in rows:
            unit = row["unit"] or ""
            try:
                ctx = self._context(proj["id"], unit)
                live = entries_mod.list_for(self, slug, unit)
                composite = ("\n".join(entries_mod.render(live)).strip() + "\n\n"
                             + interfaces.strip_types(ctx["header"]).rstrip() + "\n")
                res = self._compile(proj, composite, "")
                if res.ok:
                    continue
                if getattr(res, "infra", False):
                    continue  # the compiler crashed; that is not this unit's health
                error = (res.log or "").strip()[:1500]
                if "context.h" not in error:
                    continue  # infrastructure, not this unit
                broken.append({"unit": unit, "version": ctx["version"],
                               "entries": [e["id"] for e in live], "error": error})
            except Exception as e:  # a unit we cannot even render is its own finding
                broken.append({"unit": unit, "version": 0, "entries": [], "error": str(e)[:500]})
        if broken and report:
            self._report_unit_health(proj, broken)
        return broken

    def _report_unit_health(self, proj, broken: list[dict]) -> None:
        """File one deduped report per broken unit (created once; startup re-checks do not inflate hits)."""
        now = time.time()
        for b in broken:
            unit = b["unit"] or "base header"
            title = f"{unit}: declaration entries do not compile"
            detail = (f"get_context for any function of this unit renders a header that fails to compile "
                      f"(context v{b['version']}, entries {b['entries']}). Single-entry repairs can be "
                      f"refused when the breakage spans entries; edit_decls(remove=…, add=…) applies them "
                      f"atomically.\n\n{b['error'][:1200]}")
            with self.store.tx() as db:
                row = db.execute("SELECT id FROM reports WHERE project_id=? AND kind='bug' AND title=?",
                                 (proj["id"], title)).fetchone()
                if row:
                    db.execute("UPDATE reports SET last_seen=?, detail=COALESCE(detail, ?) WHERE id=?",
                               (now, detail, row["id"]))
                else:
                    db.execute("INSERT INTO reports(project_id,kind,title,detail,function,agent_id,created_at,"
                               "last_seen) VALUES(?,?,?,?,?,?,?,?)",
                               (proj["id"], "bug", title, detail, None, None, now, now))
                    self._event(db, proj["id"], None, "report", f"unit check: {unit} does not compile")

    def live(self, slug: str, since_event: int = 0, since_attempt: int = 0) -> dict:
        proj = self._project(slug)
        with self.store.tx() as db:
            self._expire_claims(db)
        events = self.store.all(
            "SELECT e.id, e.kind, e.detail, e.created_at, a.name AS agent FROM events e LEFT JOIN agents a "
            "ON a.id=e.agent_id WHERE e.project_id=? AND e.id>? ORDER BY e.id DESC LIMIT 60", proj["id"], since_event)
        attempts = self.store.all(
            "SELECT t.id, t.score, t.compiled, t.created_at, f.name AS function, f.n_insns, a.name AS agent "
            "FROM attempts t JOIN functions f ON f.id=t.function_id LEFT JOIN agents a ON a.id=t.agent_id "
            "WHERE f.project_id=? AND t.id>? ORDER BY t.id DESC LIMIT 80", proj["id"], since_attempt)
        claims = self.store.all(
            "SELECT f.name, f.n_insns, f.best_score, f.attempts, a.name AS agent, c.claimed_at FROM claims c "
            "JOIN functions f ON f.id=c.function_id JOIN agents a ON a.id=c.agent_id WHERE f.project_id=?", proj["id"])
        claims = [dict(c) for c in claims]
        return {"events": [dict(e) for e in reversed(events)], "attempts": [dict(t) for t in reversed(attempts)],
                "claims": claims, "overview": self.overview(slug)}

    def chat_agent(self, base: str) -> tuple[Agent, str]:
        """An identity for an agent the user talks to (Claude Code, Codex, ... connected with `decomp mcp`): `base`,
        or base-2, base-3... when another session of the same agent is active right now."""
        base = re.sub(r"[^A-Za-z0-9_.-]+", "-", base).strip("-")[:30] or "chat"
        for n in range(1, 100):
            name = base if n == 1 else f"{base}-{n}"
            row = self.store.one("SELECT id, origin, last_seen FROM agents WHERE name=?", name)
            if row is None or (row["origin"] == "chat" and (row["last_seen"] or 0) < time.time() - 600):
                break
        else:
            raise NetworkError("too many chat sessions at once")
        if row is None:
            token = self.register_agent(name, "you", trusted=True, origin="chat")
        else:
            token = "dn_" + secrets.token_urlsafe(24)
            with self.store.tx() as db:
                db.execute("UPDATE agents SET token_hash=?, last_seen=? WHERE id=?", (_hash_token(token), time.time(), row["id"]))
        return self.authenticate(token), token

    def is_chat(self, agent: Agent) -> bool:
        row = self.store.one("SELECT origin FROM agents WHERE id=?", agent.id)
        return bool(row) and row["origin"] == "chat"

    def local_agent(self, name: str) -> tuple[Agent, str]:
        """An agent identity for one runner on this machine (created on first use)."""
        row = self.store.one("SELECT id FROM agents WHERE name=?", name)
        if row is not None:
            token = "dn_" + secrets.token_urlsafe(24)
            with self.store.tx() as db:
                db.execute("UPDATE agents SET token_hash=? WHERE id=?", (_hash_token(token), row["id"]))
        else:
            token = self.register_agent(name, "you", trusted=True, origin="local")
        return self.authenticate(token), token
