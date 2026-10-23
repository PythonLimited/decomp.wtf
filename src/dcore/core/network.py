"""The coordinator: who works on what, what counts as a match, and what everyone has learned.

Every public method here is one agent-facing action. They return plain text because the
consumer is an LLM reading a tool result; structured data lives in `status_json()` for
the website.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from . import policy, scoring
from .compiler import compile_source
from ..targets.objects import FunctionObj, Reloc
from .store import Store

CLAIM_TTL = 30 * 60
RELEASE_MIN_ATTEMPTS = 20  # a handoff before this needs a filed blocker report
# A unit's header lists its functions' declarations, which is a sane thing to generate for a
# source file and an absurd one for a mega-unit like IDA's "(no debug info)" (ORION's holds
# 100k+ functions; rendering it once cost minutes and gigabytes). Units above this fall back
# to the project-wide header, which is what a human would do anyway.
UNIT_HEADER_MAX_FUNCTIONS = 1024
# Twins first (see app/twins.py): a function whose code the game has more than once (boost: how many more times)
# and isn't too big or given up on, best value per instruction first; its twins (boost -1) last, as they match for
# free once it does.
_TWINS = ("(f.boost > 0 AND f.n_insns <= 400 AND f.abandons < 2) DESC, "
          "CASE WHEN f.boost > 0 THEN (f.boost + 1) * 64 / (f.n_insns + 16) ELSE 0 END DESC, f.boost < 0, ")
STRATEGIES = {
    "easiest": _TWINS + "f.abandons > 0, f.n_insns ASC",
    # what nobody gave up on, small first; among functions of about the same size, the files closest to done (a
    # file is linked into the game once all of it matches). Leftovers agents released again and again come last,
    # or a crowd of agents spends its time passing the hardest functions around.
    "finish": _TWINS + "f.abandons ASC, (f.n_insns + 31) / 32 ASC, (SELECT COUNT(*) FROM functions g WHERE "
                       "g.project_id=f.project_id AND g.unit=f.unit AND g.status='open' AND g.mode='decompile') ASC, f.n_insns ASC",
    "closest": "f.best_score IS NULL, CAST(f.best_score AS REAL) / (f.n_insns * 100) ASC",
    "hardest": "f.n_insns DESC",
    "random": "RANDOM()",
}

MODES = ("decompile", "header", "skip")


def function_mode(fn) -> str:
    """`decompile` (the body is a target), `header` (signature/class only; never claimed) or `skip`.
    Hand-written assembly is effectively skipped for C work."""
    try:
        meta = json.loads(fn["meta"] or "{}")
    except (TypeError, ValueError, KeyError):
        meta = {}
    mode = str((fn["mode"] if "mode" in fn.keys() and fn["mode"] else meta.get("mode")) or "").strip().lower()
    if mode in ("header", "skip"):
        return mode
    return "skip" if (fn["status"] if "status" in fn.keys() else "") == "asm" else "decompile"


def rename_words(renames: dict[str, str]) -> list[tuple[re.Pattern, str]]:
    """Whole-word substitutions for a batch of renames — the one text rule shared by
    rename_symbol (one pair, gated by a regression test) and the database-sync adoption
    (many pairs, adopted from the .i64 as-is)."""
    return [(re.compile(rf"\b{re.escape(old)}\b"), new)
            for old, new in renames.items() if old and new and old != new]


def apply_word_renames(text: str, words: list[tuple[re.Pattern, str]]) -> str:
    for word, new in words:
        text = word.sub(new, text)
    return text


class NetworkError(Exception):
    """An error meant to be shown to the agent as-is."""


@dataclass
class Agent:
    id: int
    name: str
    owner: str | None
    trusted: bool = False


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _ago(ts: float | None) -> str:
    if not ts:
        return "never"
    s = int(time.time() - ts)
    return f"{s}s ago" if s < 120 else f"{s // 60}m ago" if s < 7200 else f"{s // 3600}h ago"


def _type_definition_spans(text: str, bare: str) -> list[tuple[int, int]]:
    """Span(s) of `class|struct <bare> { ... }` definitions in header text. Comments and strings are
    blanked at equal length first, so braces in them don't confuse the walker (and the spans still
    index the original text)."""
    def blank(m):
        return "".join("\n" if ch == "\n" else " " for ch in m.group(0))

    masked = re.sub(r"//[^\n]*|/\*.*?\*/", blank, text or "", flags=re.S)
    masked = re.sub(r'"(?:\\.|[^"\\])*"', blank, masked)
    spans = []
    for m in re.finditer(rf"\b(?:class|struct)\s+{re.escape(bare)}\b[^;{{]*\{{", masked):
        depth, i, end = 0, m.end() - 1, None
        while i < len(masked):
            if masked[i] == "{":
                depth += 1
            elif masked[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
            i += 1
        if end is None:
            continue
        while end < len(text) and text[end] in " \t\r\n":
            end += 1
        if end < len(text) and text[end] == ";":
            end += 1
        spans.append((m.start(), end))
    return spans


class Network:
    def __init__(self, db_path: str | Path, claim_ttl: int = CLAIM_TTL):
        self.store = Store(db_path)
        self.claim_ttl = claim_ttl
        self._pool = ThreadPoolExecutor(max_workers=8)
        self._bin_cache: dict[str, tuple[int, bytes, object]] = {}  # binary path -> (mtime, data, image)

    # ------------------------------------------------------------------ agents

    def register_agent(self, name: str, owner: str | None = None, *, trusted: bool = True, origin: str = "cli",
                       terms_accepted: bool = False) -> str:
        """Mint an agent token. Operator-created (CLI) agents are trusted; self-registered (web) agents
        start at reputation level 'new' and earn the rest through verified matches."""
        name = name.strip()
        if not name or len(name) > 40 or not all(c.isalnum() or c in "-_." for c in name):
            raise NetworkError("agent name must be 1-40 chars of [A-Za-z0-9-_.]")
        owner = (owner or "").strip()[:60] or None
        token = "dn_" + secrets.token_urlsafe(24)
        now = time.time()
        with self.store.tx() as db:
            if db.execute("SELECT 1 FROM agents WHERE lower(name)=lower(?)", (name,)).fetchone():
                raise NetworkError(f"agent name {name!r} is taken")
            db.execute(
                "INSERT INTO agents(name,owner,token_hash,created_at,trusted,origin,terms_accepted_at) VALUES(?,?,?,?,?,?,?)",
                (name, owner, _hash_token(token), now, int(trusted), origin, now if terms_accepted else None),
            )
        return token

    def authenticate(self, token: str | None) -> Agent:
        if not token:
            raise NetworkError("missing API token: add `--header \"Authorization: Bearer dn_...\"` to your MCP config")
        row = self.store.one("SELECT id,name,owner,trusted FROM agents WHERE token_hash=?", _hash_token(token))
        if row is None:
            raise NetworkError("invalid API token")
        with self.store.tx() as db:
            db.execute("UPDATE agents SET last_seen=? WHERE id=?", (time.time(), row["id"]))
        return Agent(row["id"], row["name"], row["owner"], bool(row["trusted"]))

    def _require_budget(self, agent: Agent) -> None:
        ok, why = policy.compile_budget(self.store, agent.id)
        if not ok:
            raise NetworkError(why)

    def _require_level(self, agent: Agent, what: str) -> None:
        rep = policy.reputation(self.store, agent.id)
        if not rep["level"].can_edit_context:
            raise NetworkError(f"{what} needs reputation level 'member' (one verified match). You are '{rep['level'].name}': "
                               f"match a function first; add_note is open to everyone.")

    # ---------------------------------------------------------------- helpers

    def _project(self, slug: str | None):
        if slug:
            row = self.store.one("SELECT * FROM projects WHERE slug=?", slug)
            if row is None:
                raise NetworkError(f"no project {slug!r}; call list_projects")
            return row
        rows = self.store.all("SELECT * FROM projects")
        if len(rows) == 1:
            return rows[0]
        raise NetworkError("several projects exist; pass `project` (see list_projects)")

    def _function(self, name: str, project: str | None):
        if project is None and "/" in name and "@" not in name.split("/", 1)[0]:  # project/name (fork names hold units)
            project, name = name.split("/", 1)
        if project is None:
            rows = self.store.all("SELECT * FROM functions WHERE name=?", name)
            if len(rows) > 1:
                raise NetworkError(f"{name!r} exists in several projects; pass `project`")
            row = rows[0] if rows else None
        else:
            row = self.store.one(
                "SELECT f.* FROM functions f JOIN projects p ON p.id=f.project_id WHERE p.slug=? AND f.name=?",
                project, name,
            )
        if row is None:
            raise NetworkError(f"no function {name!r}" + (f" in {project!r}" if project else ""))
        return row

    def _context(self, project_id: int, unit: str | None = ""):
        """Latest header for a translation unit, falling back to the project-wide one. Real codebases have
        one header set per source file; small projects just have the project-wide header ('' unit).
        A unit's header is written the first time the unit is touched: the confirm no longer bakes
        all 6,433 of them for a binary like ORION (that was 13+ minutes of eager work)."""
        unit = unit or ""
        if unit:
            row = self.store.one("SELECT * FROM context_versions WHERE project_id=? AND unit=? "
                                 "ORDER BY version DESC LIMIT 1", project_id, unit)
            if row is None:
                row = self._generate_unit_header(project_id, unit)
            if row is not None:
                return row
        return self.store.one("SELECT * FROM context_versions WHERE project_id=? AND unit='' "
                              "ORDER BY version DESC LIMIT 1", project_id)

    def _generate_unit_header(self, project_id: int, unit: str):
        """Generate and store a unit's header from the analysis. Falls back to the project-wide
        header when there is no analysis or the unit isn't a source file of it."""
        proj = self.store.one("SELECT * FROM projects WHERE id=?", project_id)
        analysis = None
        if proj is not None:
            try:
                analysis = self.native.analysis(proj)
            except Exception:
                analysis = None
        files = (analysis or {}).get("graph", {}).get("files", {})
        node = files.get(unit)
        if analysis is None or node is None or len(node.get("functions") or []) > UNIT_HEADER_MAX_FUNCTIONS:
            return self.store.one("SELECT * FROM context_versions WHERE project_id=? AND unit='' "
                                  "ORDER BY version DESC LIMIT 1", project_id)
        by_ea = {f["ea"]: f for f in analysis["functions"]}
        languages = {by_ea[ea].get("language") or "c" for ea in node["functions"] if ea in by_ea}
        lang = "c++" if "c++" in languages else "c"
        from . import interfaces

        header = interfaces.unit_header(analysis, unit, language=lang)
        with self.store.tx() as db:
            version = self._next_version(db, proj["id"])
            db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                       "VALUES(?,?,?,?,?,?,?)",
                       (proj["id"], version, header, None, f"generated ({lang})", time.time(), unit))
        return self.store.one("SELECT * FROM context_versions WHERE project_id=? AND unit=? "
                              "ORDER BY version DESC LIMIT 1", project_id, unit)

    def _stored_units(self, project_id: int) -> set[str]:
        """Only the units that already have a header row stored."""
        return {r["unit"] for r in self.store.all(
            "SELECT DISTINCT unit FROM context_versions WHERE project_id=? AND unit != ''", project_id)}

    def _unit_contexts(self, project_id: int) -> set[str]:
        """The units that can carry their own header: source files of the analysis with a sane
        function count (headers generate when first touched; mega-units fall back to the
        project-wide header) plus any stored ones (projects with no analysis yet)."""
        units = self._stored_units(project_id)
        proj = self.store.one("SELECT * FROM projects WHERE id=?", project_id)
        if proj is not None:
            try:
                analysis = self.native.analysis(proj)
            except Exception:
                analysis = None
            if analysis:
                for path, node in ((analysis.get("graph") or {}).get("files") or {}).items():
                    if len(node.get("functions") or []) <= UNIT_HEADER_MAX_FUNCTIONS:
                        units.add(path)
        return units

    def _effective_unit(self, fn, units: set[str]) -> str:
        return fn["unit"] if fn["unit"] in units else ""

    @staticmethod
    def _hash_only(fn) -> bool:
        return False  # every project in this build is native: target bytes materialize on demand

    def _bin_view(self, proj):
        """(data, NativeImage) for the project's binary, cached until the file changes."""
        from ..targets import formats

        cfg = json.loads(proj["config"]) if isinstance(proj["config"], (str, bytes)) else proj["config"]
        path = Path(proj["root"]) / cfg["binary"]["file"]
        try:
            mtime = path.stat().st_mtime_ns
        except OSError:
            return None, None
        cached = self._bin_cache.get(str(path))
        if cached is not None and cached[0] == mtime:
            return cached[1], cached[2]
        try:
            data = path.read_bytes()
        except OSError:
            return None, None
        image = formats.identify(data)
        if image is None:
            return None, None
        self._bin_cache[str(path)] = (mtime, data, image)
        return data, image

    def _ensure_row_code(self, fn, proj) -> bytes | None:
        """The function's target bytes, from the row when already materialized, from the binary
        otherwise (and written back so it's read once)."""
        if fn["target"] is not None:
            return fn["target"]
        from ..targets import formats

        data, image = self._bin_view(proj)
        if data is None:
            return None
        code = formats.read_bytes(data, image, fn["vram"], fn["size"])
        if code is None:
            return None
        import sqlite3

        with self.store.tx() as db:
            db.execute("UPDATE functions SET target=? WHERE id=?", (sqlite3.Binary(code), fn["id"]))
        return code

    def _ensure_row_asm(self, fn, proj) -> str:
        """The disassembly text, computed on first use and cached in the row."""
        if fn["asm"]:
            return fn["asm"]
        code = self._ensure_row_code(fn, proj)
        if code is None:
            return ""
        meta = json.loads(fn["meta"] or "{}")
        text = scoring.brief_asm(meta.get("demangled") or fn["name"], proj["arch"], code,
                                 bool(proj["big_endian"]))
        with self.store.tx() as db:
            db.execute("UPDATE functions SET asm=? WHERE id=?", (text, fn["id"]))
        return text

    def _target_obj(self, fn, proj) -> FunctionObj:
        code = self._ensure_row_code(fn, proj)
        return FunctionObj(
            name=fn["name"], arch=proj["arch"], big_endian=bool(proj["big_endian"]), code=code,
            relocs=[Reloc.from_json(r) for r in json.loads(fn["relocs"])],
        )

    def _expire_claims(self, db) -> None:
        now = time.time()
        for row in db.execute("SELECT c.function_id, c.agent_id, f.project_id, f.name FROM claims c "
                              "JOIN functions f ON f.id=c.function_id WHERE c.expires_at < ?", (now,)).fetchall():
            db.execute("UPDATE functions SET abandons=abandons+1 WHERE id=?", (row["function_id"],))
            self._event(db, row["project_id"], row["agent_id"], "expired", row["name"])
        db.execute("DELETE FROM claims WHERE expires_at < ?", (now,))

    def _event(self, db, project_id, agent_id, kind, detail) -> None:
        db.execute("INSERT INTO events(project_id,agent_id,kind,detail,created_at) VALUES(?,?,?,?,?)",
                   (project_id, agent_id, kind, detail, time.time()))

    def _agent_name(self, agent_id) -> str:
        row = self.store.one("SELECT name FROM agents WHERE id=?", agent_id) if agent_id else None
        return row["name"] if row else "?"

    def _evaluate(self, fn, proj, obj: bytes) -> tuple[FunctionObj | None, bool | None, list[str]]:
        """(candidate, verdict, problems) for a compiled object. verdict None means: decide by comparing
        fingerprints. The candidate is read through the project's platform pack (Engine overrides this)."""
        from ..targets import plat_pack

        cfg = json.loads(proj["config"]) if isinstance(proj["config"], (str, bytes)) else proj["config"]
        reader = plat_pack(cfg.get("format") or "elf").object_reader()
        return reader.extract_function(obj, fn["name"]), None, []

    def _judge(self, fn, proj, obj: bytes):
        """(candidate, Verdict | None, problems). The base has no normalized view; engines with a
        reconstructed target override this so callers can use the judge's normalized diff and gist."""
        cand, verdict, problems = self._evaluate(fn, proj, obj)
        return cand, None, problems

    def _asm_text(self, fn, proj) -> str:
        return self._ensure_row_asm(fn, proj)

    def _extra_brief(self, fn, proj) -> list[str]:
        return []

    def _seed_intro(self, fn, proj) -> str:
        """The line above a machine draft in the brief; engines whose drafts come from a
        different source (Hex-Rays, for native projects) override it."""
        return ("### Machine-generated starting point (m2c: expect wrong types and names; "
                "the context header helps)")

    # ---------------------------------------------------------------- projects

    def list_projects(self) -> str:
        rows = self.store.all(
            """SELECT p.slug, p.name, p.arch, p.description, p.config, COUNT(f.id) AS total,
                      SUM(f.status='matched') AS matched, SUM(f.size) AS bytes,
                      SUM(CASE WHEN f.status='matched' THEN f.size ELSE 0 END) AS matched_bytes
               FROM projects p LEFT JOIN functions f ON f.project_id=p.id
                 AND f.status NOT IN ('interface','excluded','library')
               GROUP BY p.id ORDER BY p.slug"""
        )
        if not rows:
            return "No projects yet."
        out = []
        for r in rows:
            pct = 100 * (r["matched_bytes"] or 0) / (r["bytes"] or 1)
            legal = json.loads(r["config"]).get("legal", {})
            out.append(f"- {r['slug']}: {r['name']} [{r['arch']}] — {r['matched'] or 0}/{r['total']} functions "
                       f"matched ({pct:.1f}% of code); legal basis: {legal.get('basis')}, contributions licensed "
                       f"{legal.get('license')}\n  {r['description']}".rstrip())
        return "\n".join(out)

    def get_context(self, project: str | None, function: str | None = None) -> str:
        fn = None
        if function:
            fn = self._function(function, project)
            proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
            unit = fn["unit"]
            ctx = self._context(proj["id"], unit)
        else:
            proj = self._project(project)
            if self._unit_contexts(proj["id"]):
                raise NetworkError(f"{proj['slug']} has one header per source file: pass `function` to get the "
                                   f"header that function compiles against")
            unit = ""
            ctx = self._context(proj["id"])
        native = getattr(self, "native", None)
        if fn is not None and native is not None and self.native_slug(proj["slug"]):
            rendered = native.header_view(fn, proj)
            return (f"// context.h for {proj['slug']} — version {ctx['version']}, rendered exactly as this "
                    f"function's next compile will see it (prepended as #include \"context.h\"):\n{rendered}")
        from . import entries as entries_mod

        live = entries_mod.list_for(self, proj["slug"], unit)
        tail = ""
        if live:
            tail = ("\n\n// declaration entries (generated header — rendered into every compile of this unit):\n"
                    + "\n".join(entries_mod.render(live)))
        return (f"// context.h for {proj['slug']} — version {ctx['version']} "
                f"(prepended to every compile as #include \"context.h\")\n{ctx['header']}{tail}")

    # ------------------------------------------------------------------ claims

    def release_claims(self, agent_name: str, project: str | None = None) -> list[str]:
        """Drop every claim this agent identity holds; returns the freed function names. A stopped
        helper or a session whose process died must not keep functions blocked for everyone else.
        No release events are written: this is cleanup, not a verdict on those functions."""
        pid = self._project(project)["id"] if project else None
        args: tuple = (agent_name,) if pid is None else (agent_name, pid)
        with self.store.tx() as db:
            rows = db.execute(
                "SELECT c.function_id AS fid, f.name AS fn FROM claims c JOIN functions f ON f.id=c.function_id "
                "JOIN agents a ON a.id=c.agent_id WHERE a.name=?" + (" AND f.project_id=?" if pid is not None else ""),
                args).fetchall()
            for r in rows:
                db.execute("DELETE FROM claims WHERE function_id=? AND agent_id=(SELECT id FROM agents WHERE name=?)",
                           (r["fid"], agent_name))
        return [r["fn"] for r in rows]

    def renew_claims(self, agent: Agent, project: str | None = None) -> int:
        """Extend this agent's leases. A local model can spend many minutes on one answer without
        touching a tool; the claim means 'this agent is still working on it', not 'it called a tool
        recently'. The session runner beats this while an API session is alive."""
        args: list = [time.time() + self.claim_ttl, agent.id]
        sql = "UPDATE claims SET expires_at=? WHERE agent_id=?"
        if project is not None:
            sql += " AND function_id IN (SELECT id FROM functions WHERE project_id=?)"
            args.append(self._project(project)["id"])
        with self.store.tx() as db:
            cur = db.execute(sql, tuple(args))
        return cur.rowcount

    def claim(self, agent: Agent, project: str | None = None, function: str | None = None,
              strategy: str = "easiest") -> str:
        fn = self.claim_row(agent, project, function, strategy)
        if fn is None:
            proj = self._project(project)
            return f"Nothing left to claim in {proj['slug']} — every open function is matched or claimed. 🎉"
        return self._brief(fn, agent, header="CLAIMED")

    def claim_row(self, agent: Agent, project: str | None = None, function: str | None = None,
                  strategy: str = "easiest"):
        """Claim (or renew) a function and return its row, or None when nothing is left."""
        if strategy not in STRATEGIES:
            raise NetworkError(f"strategy must be one of {', '.join(STRATEGIES)}")
        proj = self._project(project) if (project or function is None) else None
        now = time.time()
        with self.store.tx() as db:
            self._expire_claims(db)
            held = db.execute("SELECT f.* FROM claims c JOIN functions f ON f.id=c.function_id WHERE c.agent_id=?",
                              (agent.id,)).fetchone()
            if held is not None:
                if function and held["id"] != self._function(function, proj["slug"] if proj else None)["id"]:
                    raise NetworkError(f"you already hold {held['name']}; match it, or "
                                       f"release_function('{held['name']}') first and claim again")
                fn = held
                db.execute("UPDATE claims SET expires_at=? WHERE function_id=?", (now + self.claim_ttl, fn["id"]))
            elif function:
                fn = self._function(function, proj["slug"] if proj else None)
                if fn["status"] == "matched":
                    raise NetworkError(f"{fn['name']} is already matched; use get_function to read its source")
                if fn["status"] == "asm":
                    raise NetworkError(f"{fn['name']} is hand-written assembly: no C compiles to it, so it's left out")
                mode = function_mode(fn)
                if mode == "header":
                    raise NetworkError(f"{fn['name']} is header-only (mode=header): edit its class/method with "
                                       f"edit_type or declare_opaque, or set_mode(decompile) to work on the body")
                if mode == "skip":
                    raise NetworkError(f"{fn['name']} is skipped (mode=skip); set_mode(decompile) to claim it")
                other = db.execute("SELECT agent_id, expires_at FROM claims WHERE function_id=?", (fn["id"],)).fetchone()
                if other is not None:
                    raise NetworkError(f"{fn['name']} is claimed by {self._agent_name(other['agent_id'])} "
                                       f"for another {int(other['expires_at'] - now) // 60} min")
                busy = db.execute(
                    "SELECT a.name AS agent, f.name AS fn FROM claims c JOIN functions f ON f.id=c.function_id "
                    "JOIN agents a ON a.id=c.agent_id WHERE f.project_id=? AND f.unit=? AND c.agent_id<>? LIMIT 1",
                    (fn["project_id"], fn["unit"], agent.id)).fetchone()
                if busy is not None:
                    raise NetworkError(
                        f"{fn['unit'] or 'the base header'} is already being worked on by {busy['agent']} "
                        f"({busy['fn']}) — one agent per unit keeps the shared declaration header stable. Claim "
                        f"a function in another unit, or wait for that agent to release.")
                db.execute("INSERT INTO claims VALUES(?,?,?,?)", (fn["id"], agent.id, now, now + self.claim_ttl))
                self._event(db, fn["project_id"], agent.id, "claim", fn["name"])
            else:
                rows = db.execute(
                    f"""SELECT f.* FROM functions f WHERE f.project_id=? AND f.status='open'
                        AND f.mode='decompile'
                        AND f.id NOT IN (SELECT function_id FROM claims)
                        AND f.name NOT IN (SELECT detail FROM events WHERE project_id=? AND agent_id=? AND kind='release')
                        ORDER BY {STRATEGIES[strategy]} LIMIT 64""",
                    (proj["id"], proj["id"], agent.id),
                ).fetchall()
                rows = [r for r in rows if function_mode(r) == "decompile"]
                if not rows:
                    return None
                # A unit's declaration entries are one shared header: two agents editing raw classes
                # in the same unit invalidate each other's compiles (OSMemory/String churn). Spread
                # helpers across units first; share a unit only when every open unit already has one.
                busy = {r["unit"] for r in db.execute(
                    "SELECT f.unit FROM claims c JOIN functions f ON f.id=c.function_id "
                    "WHERE f.project_id=? AND c.agent_id<>?", (proj["id"], agent.id)).fetchall()}
                fn = next((r for r in rows if r["unit"] not in busy), rows[0])
                db.execute("INSERT INTO claims VALUES(?,?,?,?)", (fn["id"], agent.id, now, now + self.claim_ttl))
                self._event(db, fn["project_id"], agent.id, "claim", fn["name"])
        return fn

    def release(self, agent: Agent, function: str, notes: str, project: str | None = None) -> str:
        fn = self._function(function, project)
        with self.store.tx() as db:
            row = db.execute("SELECT agent_id FROM claims WHERE function_id=?", (fn["id"],)).fetchone()
            if row is None or row["agent_id"] != agent.id:
                raise NetworkError(f"you don't hold a claim on {fn['name']}")
            if 0 < fn["attempts"] < RELEASE_MIN_ATTEMPTS:
                filed = db.execute("SELECT 1 FROM reports WHERE project_id=? AND status='open' AND "
                                   "function=? LIMIT 1", (fn["project_id"], fn["name"])).fetchone()
                if filed is None:
                    raise NetworkError(
                        f"{fn['name']} has only {fn['attempts']} compile(s) — keep working. release_function is "
                        f"for a confirmed blocker after about {RELEASE_MIN_ATTEMPTS} compiles; if the tool or the "
                        f"header itself is broken, file report(kind='bug', detail=<repro>) for this function and "
                        f"release after that.")
            db.execute("DELETE FROM claims WHERE function_id=?", (fn["id"],))
            db.execute("UPDATE functions SET abandons=abandons+1 WHERE id=?", (fn["id"],))
            if notes.strip():
                db.execute("INSERT INTO notes(project_id,function_id,agent_id,text,created_at) VALUES(?,?,?,?,?)",
                           (fn["project_id"], fn["id"], agent.id, notes.strip(), time.time()))
            self._event(db, fn["project_id"], agent.id, "release", fn["name"])
        return (f"Released {fn['name']}. Your best attempt and notes are saved so the next agent starts "
                f"where you left off. Call claim_function for a new one.")

    def get_function(self, function: str, project: str | None = None, agent: Agent | None = None) -> str:
        return self._brief(self._function(function, project), agent, header="VIEW")

    def _brief(self, fn, agent: Agent | None, header: str) -> str:
        proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        ctx = self._context(proj["id"], fn["unit"])
        claim = self.store.one("SELECT * FROM claims WHERE function_id=?", fn["id"])
        lines = [f"## {header}: {proj['slug']}/{fn['name']}",
                 f"size {fn['size']} bytes, {fn['n_insns']} instructions, arch {proj['arch']}, "
                 f"context.h v{ctx['version']} ({len(ctx['header'].splitlines())} lines)"]
        if claim:
            who = "you" if agent and claim["agent_id"] == agent.id else self._agent_name(claim["agent_id"])
            lines.append(f"claimed by {who}, lease expires in {int(claim['expires_at'] - time.time()) // 60} min "
                         f"(each compile_and_diff renews it)")
        if fn["status"] == "matched":
            lines += [f"MATCHED by {self._agent_name(fn['matched_agent_id'])} {_ago(fn['matched_at'])}:",
                      "```c", fn["matched_source"].strip(), "```"]
        if self._hash_only(fn):
            lines += ["", "### Target assembly", "This is a hash-only project: the coordinator keeps a one-way fingerprint of "
                      "each function, never its code. Disassemble your own lawful copy with "
                      f"`dcore local asm <your-object.o> {fn['name']}` and diff locally with `dcore local diff`."]
        else:
            lines += ["", "### Target assembly", "```asm", scoring.compact_asm(self._asm_text(fn, proj)), "```"]
        lines += self._extra_brief(fn, proj)
        if fn["status"] != "matched":
            if fn["best_source"]:
                lines += ["", f"### Best attempt so far: score {fn['best_score']} by "
                              f"{self._agent_name(fn['best_agent_id'])} ({fn['attempts']} attempts total) — "
                              f"start from this", "```c", fn["best_source"].strip(), "```"]
            elif fn["seed"]:
                lines += ["", self._seed_intro(fn, proj), "```c", fn["seed"].strip(), "```"]
        notes = self.store.all(
            "SELECT n.text, n.created_at, a.name FROM notes n LEFT JOIN agents a ON a.id=n.agent_id "
            "WHERE n.function_id=? ORDER BY n.id DESC LIMIT 8", fn["id"])
        if notes:
            lines += ["", "### Notes from previous agents on this function"]
            lines += [f"- ({n['name']}, {_ago(n['created_at'])}) {n['text']}" for n in notes]
        pnotes = self.store.all(
            "SELECT n.text, a.name FROM notes n LEFT JOIN agents a ON a.id=n.agent_id "
            "WHERE n.project_id=? AND n.function_id IS NULL ORDER BY n.id DESC LIMIT 5", proj["id"])
        if pnotes:
            lines += ["", "### Project-wide notes (latest)"] + [f"- ({n['name']}) {n['text']}" for n in pnotes]
        if fn["unit"] and fn["unit"] in self._unit_contexts(proj["id"]):
            lines.insert(2, f"source unit {fn['unit']}: call get_context with function=\"{fn['name']}\" for its header")
        if header == "CLAIMED":
            lines += ["", "Next: read context.h with get_context, write C for this function, and iterate with "
                          "compile_and_diff until score is 0. Submit only the function itself — first line to "
                          "closing brace; context.h is included automatically and declarations belong in it "
                          "(edit_context). Native projects: types come from the registry (search_types)."]
        return "\n".join(lines)

    # --------------------------------------------------------- compile & diff

    def compile_and_diff(self, agent: Agent, function: str, source: str, project: str | None = None) -> str:
        return self.attempt(agent, function, source, project)["text"]

    def attempt(self, agent: Agent, function: str, source: str, project: str | None = None) -> dict:
        """Compile, score and record one attempt. Returns {"text", "score", "matched"} (score None: didn't compile)."""
        self._require_budget(agent)
        fn = self._function(function, project)
        proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        now = time.time()

        # Claim bookkeeping first: you can't score (or get credit) on someone else's function.
        with self.store.tx() as db:
            self._expire_claims(db)
            claim = db.execute("SELECT agent_id FROM claims WHERE function_id=?", (fn["id"],)).fetchone()
            scratch = fn["status"] == "matched"
            if not scratch:
                if claim is None:
                    held = db.execute("SELECT f.name FROM claims c JOIN functions f ON f.id=c.function_id "
                                      "WHERE c.agent_id=?", (agent.id,)).fetchone()
                    if held:
                        raise NetworkError(
                            f"you hold a claim on `{held['name']}` — to work on `{fn['name']}`, "
                            f"release_function('{held['name']}') first, then claim_function('{fn['name']}')")
                    db.execute("INSERT INTO claims VALUES(?,?,?,?)", (fn["id"], agent.id, now, now + self.claim_ttl))
                    self._event(db, fn["project_id"], agent.id, "claim", fn["name"])
                elif claim["agent_id"] != agent.id:
                    raise NetworkError(f"{fn['name']} is claimed by {self._agent_name(claim['agent_id'])}")
                else:
                    db.execute("UPDATE claims SET expires_at=? WHERE function_id=?", (now + self.claim_ttl, fn["id"]))

        ctx = self._context(proj["id"], fn["unit"])
        result = self._compile(proj, ctx["header"], source, fn=fn)

        if not result.ok:
            if getattr(result, "infra", False):
                # the compiler never ran: counting this as a failed attempt would poison best_score,
                # the stall nudge and the GUI ("best attempt didn't compile") with a host problem
                return {"text": f"⚠️ THE COMPILER DID NOT RUN — infrastructure crash, not your code. "
                                f"No attempt was recorded; retrying is safe.\n{result.log.strip()}",
                        "score": None, "matched": False, "infra": True}
            self._record(fn, agent, None, source, ctx["version"])
            note = ""
            # the mismatches that cost the most laps (overload/redeclaration/conversion) all come
            # down to the declaration and the definition disagreeing with the binary's signature —
            # which we know exactly. One authoritative line beats three guessing compiles.
            if re.search(r"\b(C2556|C2372|C2511|C2440|C2664)\b", result.log or ""):
                try:
                    meta = json.loads(fn["meta"] or "{}")
                except (TypeError, ValueError):
                    meta = {}
                bits = [str(meta.get("demangled") or "").strip()]
                if meta.get("signature"):
                    bits.append(f"`{meta['signature']}`")
                bits = [b for b in bits if b]
                if bits:
                    note = ("\n💡 this is the binary's function: " + " — ".join(bits)
                            + ". The header declaration and your definition must both match it exactly "
                              "(return type, const, calling convention).")
            return {"text": f"❌ COMPILE ERROR (context v{ctx['version']})\n{result.log.strip()}{note}",
                    "score": None, "matched": False}

        cand, verdict, problems = self._judge(fn, proj, result.obj)
        if cand is None:
            bad = next((p for p in problems if p.startswith("THE COMPILED OBJECT IS NOT READABLE")), None)
            if bad:
                return {"text": f"⚠️ {bad} No attempt was recorded; retrying is safe.",
                        "score": None, "matched": False, "infra": True}
            self._record(fn, agent, None, source, ctx["version"])
            return {"text": f"❌ Compiled, but the object has no function named `{fn['name']}`. "
                            f"Define it with exactly that name (non-static).", "score": None, "matched": False}
        if self._hash_only(fn):
            fp_match = cand.fingerprint() == fn["fingerprint"]
            matched_now = fp_match and not scratch
            self._record(fn, agent, 0 if fp_match else None, source, ctx["version"], matched=fp_match, compiled=True)
            if matched_now:
                return {"text": f"✅ MATCH! {fn['name']} matches the target fingerprint. Credited to {agent.name}; "
                                f"your claim is released.", "score": 0, "matched": True}
            if scratch and fp_match:
                return {"text": f"✅ re-match: the source is byte-identical again and replaces the stored one "
                                f"for {fn['name']}.", "score": 0, "matched": True}
            return {"text": "❌ No match. This is a hash-only project, so the coordinator can only say match / no match. "
                            f"For a scored diff, run `dcore local diff <your-object.o> {fn['name']} <your.c>` "
                            "against your own lawful copy.", "score": None, "matched": False}
        if verdict is not None:
            d = verdict.diff          # link-layer spellings already adopted from the candidate
            matched = verdict.match
        else:
            d = scoring.diff(self._target_obj(fn, proj), cand)
            matched = d.bytes_match
        d = scoring.DiffResult(0 if matched else max(1, d.score), d.max_score, d.rows, matched, gist=d.gist)
        # a byte-identical re-check of an already-matched function refreshes its stored source too
        # (it is not inferior by definition); anything else leaves the record untouched
        self._record(fn, agent, d.score, source, ctx["version"], matched=d.bytes_match)

        if scratch:
            head = (f"(re-match — {fn['name']} was already matched; the byte-identical source replaces the "
                    f"stored one)" if d.bytes_match
                    else f"(scratch — {fn['name']} was already matched) score {d.score}")
        elif d.bytes_match:
            return {"text": f"✅ MATCH! {fn['name']} is byte-identical to the target ({fn['n_insns']} instructions). "
                            f"Credited to {agent.name}; your claim is released. Call claim_function for the next one.",
                    "score": 0, "matched": True}
        else:
            best = self.store.one("SELECT best_score FROM functions WHERE id=?", fn["id"])["best_score"]
            head = (f"score {d.score} ({scoring.percent_text(d.percent)} match) — best so far {best}. "
                    f"Target {len([r for r in d.rows if r[1]])} insns, yours {len([r for r in d.rows if r[2]])}.")
            if d.rows and all(m == " " for m, _, _ in d.rows):
                head += ("\nNOT A MATCH YET: every instruction reads the same, but the bytes differ"
                         + (" because of the linking notes at the end: fix those." if problems else
                            ": an encoding the listing doesn't show (branch form, an immediate, a relocation)."))
        warn = f"\ncompiler output:\n{result.log.strip()}" if result.log.strip() else ""
        gist_line = scoring.gist_text(d.gist)
        if gist_line:
            head += f"\n{gist_line}"
        native = getattr(self, "native_slug", None)
        if (result.log and project and native and native(project)
                and re.search(r"has not been declared|was not declared in this scope|does not name a type|"
                              r"has no member named|has no member", result.log)):
            warn += ("\n\n[hint] the header doesn't know a type this code uses (or one of its members): "
                     "`search_types` it — another agent may have declared it already — or create it with "
                     "`declare_type` plus `edit_type(set_member)` for its fields, and use the class instead "
                     "of declaring it inline. Several related edits: `lock_registry`, stage with session=…, "
                     "`unlock_registry` — one verification for the batch.")
        if problems:
            warn += "\nwhen linking your code at the function's address:\n" + "\n".join(f"- {p}" for p in problems)
        return {"text": f"{head}\n{d.render()}{warn}{self.stall_note(fn['id'], agent.id)}", "score": d.score, "matched": False}

    def stall_note(self, function_id: int, agent_id: int, after: int = 4) -> str:
        """A nudge once an agent's last `after` compiles of a function didn't beat its best: a plateau
        is a signal to change the shape, not to hand the function off. `release` enforces the real
        threshold (~20 compiles or a filed blocker report)."""
        rows = self.store.all("SELECT score FROM attempts WHERE function_id=? AND agent_id=? ORDER BY id DESC LIMIT 16",
                              function_id, agent_id)
        best, since = None, 0
        for r in reversed(rows):
            if r["score"] is not None and (best is None or r["score"] < best):
                best, since = r["score"], 0
            else:
                since += 1
        if since < after:
            return ""
        return (f"\n\n⏭ No better in your last {since} compiles. Change something material before concluding it is "
                f"stuck — control flow/structure first, registers last. release_function is for about "
                f"{RELEASE_MIN_ATTEMPTS} compiles or a confirmed blocker you filed as a report; the next agent starts "
                f"from your best attempt and notes, not from your conversation.")

    def _record(self, fn, agent: Agent, score: int | None, source: str, ctx_version: int, matched: bool = False,
                compiled: bool | None = None, via: str = "agent"):
        now = time.time()
        compiled = score is not None if compiled is None else compiled
        with self.store.tx() as db:
            db.execute("INSERT INTO attempts(function_id,agent_id,score,compiled,context_version,source,created_at,via) "
                       "VALUES(?,?,?,?,?,?,?,?)", (fn["id"], agent.id, score, compiled, ctx_version, source, now, via))
            db.execute("UPDATE functions SET attempts=attempts+1 WHERE id=?", (fn["id"],))
            if score is not None:
                db.execute("UPDATE functions SET best_score=?, best_source=?, best_agent_id=? "
                           "WHERE id=? AND status='open' AND (best_score IS NULL OR best_score > ?)",
                           (score, source, agent.id, fn["id"], score))
            if matched:
                db.execute("UPDATE functions SET status='matched', matched_source=?, matched_agent_id=?, "
                           "matched_at=?, best_score=0, best_source=? WHERE id=?",
                           (source, agent.id, now, source, fn["id"]))
                db.execute("DELETE FROM claims WHERE function_id=?", (fn["id"],))
                self._event(db, fn["project_id"], agent.id, "match", fn["name"])

    # -------------------------------------------------------- shared context

    def edit_context(self, agent: Agent, project: str | None, old: str, new: str, message: str,
                     function: str | None = None) -> str:
        """Exact-string edit of a header. Accepted only if every already-matched function compiled against
        that header still matches with the new one — that's the project's test suite."""
        self._require_level(agent, "Editing the shared header")
        if function:
            fn = self._function(function, project)
            proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
            unit = self._effective_unit(fn, self._unit_contexts(proj["id"]))
        else:
            proj = self._project(project)
            if self._unit_contexts(proj["id"]):
                raise NetworkError(f"{proj['slug']} has one header per source file: pass `function` to edit the "
                                   f"header that function compiles against")
            unit = ""
        if not message.strip():
            raise NetworkError("give a short commit message explaining the change")
        if not old:
            # appends map to a raw declaration entry: the generated-header world has one editable
            # layer, and it is gated exactly like declarations (a breaking append is withdrawn)
            try:
                return self.declare_entry(agent, project, new, "raw", function)
            except NetworkError as e:
                return f"❌ REJECTED: {e}"
        # replacement: only a live declaration entry's own text can be replaced — the stored header
        # text is the frozen legacy layer now
        from . import entries as entries_mod

        live = entries_mod.list_for(self, proj["slug"], unit)
        target = next((e for e in live if (e["body"] or "").count(old) == 1), None)
        if target is None:
            raise NetworkError(
                "headers are generated now: `old` matches no live declaration entry — use declare/undeclare "
                "(list_decls shows the entries); if the text is in the frozen legacy header, promote it with "
                "promote_legacy(function=…, old=…, new=…)")
        old_body = target["body"]
        pos = entries_mod.position(target)  # an edit keeps its place: ordering is part of the meaning
        entries_mod.remove(self, proj["slug"], unit, entry_id=target["id"], agent=agent)
        try:
            out = self.declare_entry(agent, project, old_body.replace(old, new, 1), target["kind"], function,
                                     _order=pos)
        except NetworkError as e:
            entries_mod.restore(self, proj["slug"], unit, target["id"], agent=agent)
            return f"❌ REJECTED: {e}"
        if out.startswith("❌"):
            entries_mod.restore(self, proj["slug"], unit, target["id"], agent=agent)
            return out.replace("the entry was withdrawn", "the edit was withdrawn (original restored)")
        return out.replace("✅ entry", "✅ entry (edited)")

    def _unit_of(self, proj, function: str | None) -> str:
        """The unit a function resolves to ('' = the project-wide header)."""
        if function:
            fn = self._function(function, proj["slug"])
            return self._effective_unit(fn, self._unit_contexts(proj["id"]))
        if self._unit_contexts(proj["id"]):
            raise NetworkError(f"{proj['slug']} has one header per source file: pass `function` to pick the unit")
        return ""

    def declare_entry(self, agent: Agent, project: str | None, body: str, kind: str = "prototype",
                      function: str | None = None, _order: float | None = None) -> str:
        """Add a structured declaration entry to the unit's generated header (headers are rendered
        from these + the registry). Accepted only when the unit's matched functions still compile
        and match with it; a breaking entry is withdrawn again."""
        self._require_level(agent, "Editing the shared header")
        from . import entries as entries_mod

        proj = self._project(project)
        unit = self._unit_of(proj, function)
        self._member_fence(proj, body, unit)
        entry = entries_mod.add(self, proj["slug"], unit, kind, body, agent=agent, ord=_order)
        members = self._matched_using(proj, unit)
        units = self._unit_contexts(proj["id"])
        from . import interfaces

        ctx = self._context(proj["id"], unit)
        live = entries_mod.list_for(self, proj["slug"], unit)
        composite = ("\n".join(entries_mod.render(live)).strip() + "\n\n"
                     + interfaces.strip_types(ctx["header"]).rstrip() + "\n")
        broken = self.regression_test(proj, composite, only=members,
                                      header_for=lambda fn: self._context(
                                          proj["id"], self._effective_unit(fn, units))["header"])
        if broken:
            entries_mod.remove(self, proj["slug"], unit, entry_id=entry["id"])
            if broken[0][0] == "<header>":  # nothing matched: the parse check itself failed
                return (f"❌ REJECTED: the header (with this declaration) doesn't compile on its own; "
                        f"the entry was withdrawn.\n{broken[0][1]}")
            listing = "\n".join(f"- {name}: {why}" for name, why in broken[:10])
            return (f"❌ REJECTED: the declaration breaks {len(broken)} already-matched function(s); "
                    f"the entry was withdrawn.\n{listing}")
        return (f"✅ entry #{entry['id']} declared in {unit or 'the base header'}: `{entry['body']}` "
                f"({entry['kind']}" + (f", name {entry['name']}" if entry["name"] else "")
                + f") — all {len(members)} matched function(s) here still match. "
                f"See the exact render with get_context(function=…).")

    def undeclare_entry(self, agent: Agent, project: str | None, name: str = "", entry: int | None = None,
                        function: str | None = None) -> str:
        """Tombstone one live entry by declared name or id; a removal that breaks a matched
        function is withdrawn (the entry is restored)."""
        self._require_level(agent, "Editing the shared header")
        from . import entries as entries_mod

        proj = self._project(project)
        unit = self._unit_of(proj, function)
        removed = entries_mod.remove(self, proj["slug"], unit, entry_id=entry or None,
                                     name=name or None, agent=agent)
        members = self._matched_using(proj, unit)
        units = self._unit_contexts(proj["id"])
        from . import interfaces

        ctx = self._context(proj["id"], unit)
        live = entries_mod.list_for(self, proj["slug"], unit)
        composite = ("\n".join(entries_mod.render(live)).strip() + "\n\n"
                     + interfaces.strip_types(ctx["header"]).rstrip() + "\n")
        broken = self.regression_test(proj, composite, only=members,
                                      header_for=lambda fn: self._context(
                                          proj["id"], self._effective_unit(fn, units))["header"])
        if broken:
            restored = entries_mod.restore(self, proj["slug"], unit, removed["id"], agent=agent)
            if broken[0][0] == "<header>":
                return (f"❌ REJECTED: without that declaration the header doesn't compile on its own; "
                        f"the entry was restored as #{restored['id']}.\n{broken[0][1]}")
            listing = "\n".join(f"- {name}: {why}" for name, why in broken[:10])
            return (f"❌ REJECTED: removing it breaks {len(broken)} already-matched function(s); the entry "
                    f"was restored as #{restored['id']}.\n{listing}")
        return (f"✅ entry #{removed['id']} removed from {unit or 'the base header'} "
                f"(all {len(members)} matched function(s) still match). "
                f"See the exact render with get_context(function=…).")

    def list_entries(self, agent: Agent, project: str | None, function: str | None = None) -> str:
        """The live declaration entries behind the unit's generated header."""
        from . import entries as entries_mod

        proj = self._project(project)
        unit = self._unit_of(proj, function)
        live = entries_mod.list_for(self, proj["slug"], unit)
        head = f"entries for {unit or 'the base header'} ({len(live)} live):"
        if not live:
            return head + "\n  (none — declare the prototypes/statics the functions here need)"
        lines = [head]
        for e in live:
            lines.append(f"  #{e['id']:<4} {e['kind']:<9} {e['name'] or '':<28} {e['body']}")
        return "\n".join(lines)

    def _member_fence(self, proj, body: str, unit: str = "") -> None:
        """Refuse the file-scope `Class::method(...)` prototype. It renders at the top of the header,
        before the namespaces/class exist, so it can never compile — the gate would withdraw it — and
        the right edit is adding the member to its class, not a free declaration."""
        from . import entries as entries_mod

        hit = entries_mod.file_scope_qualified_call(body)
        if not hit:
            return
        qualified, method = hit
        cls = qualified.rsplit("::", 1)[0]
        if self._known_type(proj, cls, unit):
            raise NetworkError(
                f"`{qualified}` is a member of class `{cls}` — a file-scope prototype of a class member "
                f"never compiles (it renders before the class exists, and the gate withdraws it). Add it "
                f"inside the class instead: add_method(name=\"{cls}\", method=\"{method}\", ret=…, "
                f"params=…, static=…). If `{cls}` is still defined in the frozen seed (look for it in "
                f"get_context), call promote_type(\"{cls}\", function=…) first so the registry owns the "
                f"definition and your edit renders.")
        raise NetworkError(
            f"`{qualified}` is a qualified name at file scope — C++ needs its namespace in scope. "
            f"Wrap the declaration in its namespaces as one entry, e.g. `namespace "
            f"{cls.split('::')[0]} {{ namespace … {{ … }} }}`; if it is a class member, use "
            f"add_method(name=\"{cls}\", method=\"{method}\", …).")

    def _known_type(self, proj, cls: str, unit: str = "") -> bool:
        """Whether we know `cls` as a class/struct: the registry's merged types, or the unit's stored
        (frozen) header. Used only to word the member fence, so failures fall back to the generic text."""
        bare = cls.rsplit("::", 1)[-1]
        try:
            from . import registry as reg

            native = getattr(self, "native", None)
            analysis = native.analysis(proj) if native is not None else None
            types = reg.view(analysis or {"types": []}, reg.load(self, proj["slug"]))
            keys = {reg.key_of(t) for t in types}
            if cls in keys or any(k.rsplit("::", 1)[-1] == bare for k in keys):
                return True
        except Exception:
            pass
        try:
            from . import interfaces

            ctx = self._context(proj["id"], unit)
            visible = (ctx["header"] if ctx else "").split(interfaces._TYPE_MARK_BEGIN)[0]
            return bool(re.search(rf"\b(?:class|struct)\s+{re.escape(bare)}\b", visible))
        except Exception:
            return False

    def edit_entries(self, agent: Agent, project: str | None, remove: list | None = None,
                     add: list[dict] | None = None, function: str | None = None) -> str:
        """One atomic, gated edit of a unit's declaration entries: every removal and addition is
        applied together and verified as the resulting header. This is the repair path for a unit
        whose breakage is spread over more than one entry — removing either alone still leaves the
        other breaking every compile, so single-entry edits are (correctly) refused."""
        self._require_level(agent, "Editing the shared header")
        from . import entries as entries_mod
        from . import interfaces

        proj = self._project(project)
        unit = self._unit_of(proj, function)
        remove, add = list(remove or []), list(add or [])
        if not remove and not add:
            raise NetworkError("edit_decls needs entries to remove and/or declarations to add")
        if any(not isinstance(a, dict) or not str(a.get("body") or "").strip() for a in add):
            raise NetworkError('add must be a JSON array like [{"kind": "prototype", "body": "int f(void);"}]')
        for spec in add:
            self._member_fence(proj, spec["body"], unit)
        removed: list[dict] = []
        added: list[dict] = []
        try:
            for item in remove:
                if isinstance(item, int) or (isinstance(item, str) and item.strip().lstrip("#").isdigit()):
                    row = entries_mod.remove(self, proj["slug"], unit,
                                             entry_id=int(str(item).strip().lstrip("#")), agent=agent)
                else:
                    row = entries_mod.remove(self, proj["slug"], unit, name=str(item).strip(), agent=agent)
                removed.append(row)
            for spec in add:
                added.append(entries_mod.add(self, proj["slug"], unit, spec.get("kind") or "prototype",
                                             spec["body"], agent=agent))
            members = self._matched_using(proj, unit)
            units = self._unit_contexts(proj["id"])
            ctx = self._context(proj["id"], unit)
            live = entries_mod.list_for(self, proj["slug"], unit)
            composite = ("\n".join(entries_mod.render(live)).strip() + "\n\n"
                         + interfaces.strip_types(ctx["header"]).rstrip() + "\n")
            broken = self.regression_test(proj, composite, only=members,
                                          header_for=lambda fn: self._context(
                                              proj["id"], self._effective_unit(fn, units))["header"])
        except NetworkError:
            self._rollback_entries(proj, unit, removed, added)
            raise
        if broken:
            self._rollback_entries(proj, unit, removed, added)
            if broken[0][0] == "<header>":
                return (f"❌ REJECTED: the header (with this edit) doesn't compile on its own; nothing "
                        f"changed.\n{broken[0][1]}")
            listing = "\n".join(f"- {name}: {why}" for name, why in broken[:10])
            return (f"❌ REJECTED: the edit breaks {len(broken)} already-matched function(s); nothing "
                    f"changed.\n{listing}")
        what = []
        if removed:
            what.append("removed " + ", ".join(f"#{r['id']}" for r in removed))
        if added:
            what.append("added " + ", ".join(f"#{a['id']} ({a['kind']} {a['name']})" for a in added))
        return (f"✅ entry set edited in {unit or 'the base header'}: " + "; ".join(what)
                + f" — all {len(members)} matched function(s) here still match. "
                f"See the exact render with get_context(function=…).")

    def _rollback_entries(self, proj, unit: str, removed: list[dict], added: list[dict]) -> None:
        """Undo a batch that failed validation, restoring every removed entry at its old position."""
        from . import entries as entries_mod

        for a in reversed(added):
            try:
                entries_mod.remove(self, proj["slug"], unit, entry_id=a["id"])
            except NetworkError:
                pass
        for r in removed:
            entries_mod.restore(self, proj["slug"], unit, r["id"])

    def promote_type(self, agent: Agent, project: str | None, name: str,
                     function: str | None = None, message: str = "") -> str:
        """Free a type definition from the frozen legacy header so the registry owns it. Once the
        definition is gone, the generated projection renders the registry's version and edit_type /
        add_method changes actually reach the compile. Gated like every header edit: if the unit's
        matched functions need the old text, nothing changes. The registry must already describe the
        type (from debug info or declare_type) — promotion hands it the pen, it does not invent it."""
        self._require_level(agent, "Editing the shared header")
        from . import entries as entries_mod
        from . import interfaces
        from . import registry as reg

        proj = self._project(project)
        unit = self._unit_of(proj, function)
        row = self.store.one("SELECT header FROM context_versions WHERE project_id=? AND unit=? "
                             "ORDER BY version DESC LIMIT 1", proj["id"], unit)
        if row is None:
            raise NetworkError("this unit has no stored header to promote from")
        header = row["header"] or ""
        mark = interfaces._TYPE_MARK_BEGIN
        idx = header.find(mark)
        before, after = (header[:idx], header[idx:]) if idx >= 0 else (header, "")
        bare = name.rsplit("::", 1)[-1]
        native = getattr(self, "native", None)
        analysis = native.analysis(proj) if native is not None else None
        types = reg.view(analysis or {"types": []}, reg.load(self, proj["slug"]))
        known = next((t for t in types if reg.key_of(t).rsplit("::", 1)[-1] == bare), None)
        if known is None:
            raise NetworkError(
                f"the registry doesn't describe {name!r} — after removing the frozen definition nothing "
                f"would render it. Declare it first (declare_type + edit_type set_member), then promote_type "
                f"so the registry's version takes over.")
        spans = _type_definition_spans(before, bare)
        if not spans:
            raise NetworkError(f"no definition of {bare!r} in this unit's stored header — it may already be "
                               f"generated; check get_context(function=…)")
        if len(spans) > 1:
            raise NetworkError(f"{len(spans)} definitions of {bare!r} in this unit's stored header are "
                               f"ambiguous; use promote_legacy with the exact text instead")
        start, end = spans[0]
        stripped = before[:start] + before[end:] + after
        members = self._matched_using(proj, unit)
        live = entries_mod.list_for(self, proj["slug"], unit)
        composite = ("\n".join(entries_mod.render(live)).strip() + "\n\n"
                     + interfaces.strip_types(stripped).rstrip() + "\n")
        broken = self.regression_test(proj, composite, only=members, header_for=lambda fn: stripped)
        if broken:
            if broken[0][0] == "<header>":
                return (f"❌ REJECTED: without the frozen definition the header doesn't compile on its "
                        f"own; nothing changed.\n{broken[0][1]}")
            listing = "\n".join(f"- {name}: {why}" for name, why in broken[:10])
            return (f"❌ REJECTED: the registry's {bare} can't replace the frozen definition — "
                    f"{len(broken)} matched function(s) broke; nothing changed.\n{listing}\n"
                    f"If the registry is missing members, add them with add_method/edit_type and retry; if the "
                    f"frozen class carries inline bodies you need verbatim, move the whole definition with "
                    f"promote_legacy(old=<exact text>) instead — promotion needs the registry to be complete.")
        with self.store.tx() as db:
            version = self._next_version(db, proj["id"])
            db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                       "VALUES(?,?,?,?,?,?,?)",
                       (proj["id"], version, stripped, agent.id,
                        (message or f"promoted type {name} to the registry").strip(), time.time(), unit))
            self._event(db, proj["id"], agent.id, "context",
                        f"v{version}{f' ({unit})' if unit else ''}: freed type {bare} for the registry")
        return (f"✅ type `{name}` is registry-owned now (v{version}); its frozen definition left the header "
                f"and the generated projection takes over. {len(members)} matched function(s) re-checked. "
                f"Edit it with edit_type/add_method; see the exact render with get_context(function=…).")

    def promote_legacy(self, agent: Agent, project: str | None, old: str, new: str = "", kind: str = "raw",
                       function: str | None = None, message: str = "") -> str:
        """Move a declaration out of the frozen legacy header and into the generated entries — the
        sanctioned way to edit frozen text. The old text leaves the stored header (a new legacy
        version holds the rest), the new text (default: the same text) becomes an entry of `kind`, and
        the composite is gated against the unit's matched functions. Typical use: promote a `struct X`
        seed line so it can be re-declared as `class X` — the kind changes the MSVC mangling (U vs V)."""
        self._require_level(agent, "Editing the shared header")
        from . import entries as entries_mod
        from . import interfaces

        old = (old or "").strip("\n")
        if not old.strip():
            raise NetworkError("promote_legacy needs the exact text to move out of the stored header")
        proj = self._project(project)
        unit = self._unit_of(proj, function)
        row = self.store.one("SELECT header FROM context_versions WHERE project_id=? AND unit=? "
                             "ORDER BY version DESC LIMIT 1", proj["id"], unit)
        if row is None:
            raise NetworkError("this unit has no stored header to promote from")
        header = row["header"] or ""
        # The text being promoted lives in the VISIBLE part; never edit the generated block itself.
        from . import interfaces as ifc

        mark = ifc._TYPE_MARK_BEGIN
        end_mark = ifc._TYPE_MARK_END
        begin_idx = header.find(mark)
        end_idx = header.find(end_mark)
        # The generated block can sit before OR after the visible legacy text (older stored
        # versions put it first). Search the visible parts on both sides, never the block itself.
        if begin_idx >= 0 and end_idx > begin_idx:
            head = header[:begin_idx]
            block = header[begin_idx:end_idx + len(end_mark)]
            tail = header[end_idx + len(end_mark):]
            visible_count = head.count(old) + tail.count(old)
            if visible_count == 1:
                if old in tail:
                    stripped_header = head + block + tail.replace(old, "", 1)
                else:
                    stripped_header = head.replace(old, "", 1) + block + tail
            else:
                stripped_header = header
        else:
            visible_count = header.count(old)
            stripped_header = header.replace(old, "", 1)
        if visible_count != 1:
            raise NetworkError(f"the text must occur exactly once in the stored header's visible part "
                               f"(found {visible_count})")
        entry = entries_mod.add(self, proj["slug"], unit, kind, (new or old).strip(), agent=agent)
        members = self._matched_using(proj, unit)
        live = entries_mod.list_for(self, proj["slug"], unit)
        composite = ("\n".join(entries_mod.render(live)).strip() + "\n\n"
                     + ifc.strip_types(stripped_header).rstrip() + "\n")
        broken = self.regression_test(proj, composite, only=members,
                                      header_for=lambda fn: stripped_header)
        if broken:
            entries_mod.remove(self, proj["slug"], unit, entry_id=entry["id"], agent=agent)
            if broken[0][0] == "<header>":
                return (f"❌ REJECTED: the promoted header doesn't compile on its own; nothing changed.\n"
                        f"{broken[0][1]}")
            listing = "\n".join(f"- {name}: {why}" for name, why in broken[:10])
            return (f"❌ REJECTED: moving it breaks {len(broken)} already-matched function(s); nothing "
                    f"changed.\n{listing}")
        with self.store.tx() as db:
            version = self._next_version(db, proj["id"])
            db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                       "VALUES(?,?,?,?,?,?,?)", (proj["id"], version, stripped_header, agent.id,
                                                 (message or f"promoted to entry #{entry['id']}").strip(),
                                                 time.time(), unit))
            self._event(db, proj["id"], agent.id, "context",
                        f"v{version}{f' ({unit})' if unit else ''}: promoted to entry #{entry['id']}")
        verified = max(0, len(members) - (1 if broken and broken[0][0] == '<header>' else 0))
        return (f"✅ entry #{entry['id']} ({entry['kind']}) now declares it; the stored header no longer "
                f"does (v{version}). {verified} matched function(s) re-checked. If the mangling must "
                f"change (class vs struct), replace the entry text now (edit_context/undeclare+declare). "
                f"See the exact render with get_context(function=…).")

    def set_mode(self, agent: Agent, function: str, mode: str, note: str = "",
                 project: str | None = None) -> str:
        """Choose whether a function is a decompilation target (`decompile`), a header-only
        signature/class (`header`), or ignored (`skip`). A matched function cannot be hidden this
        way; reset its match first. Setting header/skip drops any live claim on it."""
        self._require_level(agent, "Choosing a function mode")
        mode = (mode or "").strip().lower()
        if mode not in MODES:
            return f"❌ mode must be one of {', '.join(MODES)}"
        fn = self._function(function, project)
        current = function_mode(fn)
        if current == mode:
            return f"✅ {fn['name']} is already `{mode}`."
        if fn["status"] == "matched" and mode != "decompile":
            return (f"❌ {fn['name']} is matched; changing it to `{mode}` would hide a real match. "
                    f"Reset the match first if that is intended.")
        meta = json.loads(fn["meta"] or "{}")
        meta.pop("mode", None)  # older rows kept it here; the column is authoritative now
        if note:
            meta["mode_note"] = note.strip()
        with self.store.tx() as db:
            db.execute("UPDATE functions SET mode=?, meta=? WHERE id=?",
                       (mode, json.dumps(meta, sort_keys=True), fn["id"]))
            if mode != "decompile":
                db.execute("DELETE FROM claims WHERE function_id=?", (fn["id"],))
            self._event(db, fn["project_id"], agent.id, "mode", f"{fn['name']}: {current} -> {mode}")
        detail = {
            "decompile": "the body is a target again",
            "header": "no body will be claimed; its signature/class stays available to callers",
            "skip": "ignored by the work queue and the header",
        }[mode]
        return f"✅ {fn['name']} is now `{mode}` — {detail}."

    def rename_symbol(self, agent: Agent, project: str | None, old: str, new: str, message: str = "") -> str:
        """Project-wide refactor: rename an identifier (field, type, global, function param...) in every
        header *and* in every matched source / best attempt, then regression-test the result.
        The rename is textual (whole words), so it is meant for unique names like `unk_1C` or `func_80012345`."""
        self._require_level(agent, "Renaming across the project")
        proj = self._project(project)
        ident = re.compile(r"^[A-Za-z_]\w*$")
        if not (ident.match(old) and ident.match(new)):
            raise NetworkError("old and new must be C identifiers")
        words = rename_words({old: new})
        all_units = self._unit_contexts(proj["id"])
        for _ in range(3):
            # scan only headers that exist: in the lazy world most units have none until someone
            # works on them, and a header that was never written can't contain the identifier
            scanning = {""} | self._stored_units(proj["id"])
            current = {u: self._context(proj["id"], u) for u in scanning}
            changed = {}
            for u, c in current.items():
                text = apply_word_renames(c["header"], words)
                if text != c["header"]:
                    changed[u] = text
            if not changed:
                raise NetworkError(f"`{old}` does not occur in any header")
            matched = self.store.all("SELECT * FROM functions WHERE project_id=? AND status='matched'", proj["id"])
            rewritten = {r["id"]: apply_word_renames(r["matched_source"], words) for r in matched}

            def header_for(fn):
                u = self._effective_unit(fn, all_units)
                if u in changed:
                    return changed[u]
                ctx = current.get(u) or self._context(proj["id"], u)
                return ctx["header"]
            broken = self.regression_test(proj, None, sources=rewritten, only=matched, header_for=header_for)
            if broken:
                listing = "\n".join(f"- {name}: {why}" for name, why in broken[:10])
                return f"❌ REJECTED: renaming breaks {len(broken)} matched function(s).\n{listing}"
            msg = message.strip() or f"rename {old} -> {new}"
            with self.store.tx() as db:
                n_matched = db.execute("SELECT COUNT(*) AS n FROM functions WHERE project_id=? AND status='matched'",
                                       (proj["id"],)).fetchone()["n"]
                if n_matched != len(matched) or any(self._latest_version(db, proj["id"], u) != current[u]["version"]
                                                    for u in changed):
                    continue
                for u, header in changed.items():
                    version = self._next_version(db, proj["id"])
                    db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                               "VALUES(?,?,?,?,?,?,?)", (proj["id"], version, header, agent.id, msg, time.time(), u))
                for fid, src in rewritten.items():
                    db.execute("UPDATE functions SET matched_source=?, best_source=? WHERE id=?", (src, src, fid))
                for r in db.execute("SELECT id, best_source FROM functions WHERE project_id=? AND status='open' "
                                    "AND best_source IS NOT NULL", (proj["id"],)).fetchall():
                    db.execute("UPDATE functions SET best_source=? WHERE id=?",
                               (apply_word_renames(r["best_source"], words), r["id"]))
                self._event(db, proj["id"], agent.id, "context", f"{msg} ({len(changed)} header(s))")
            ida_note = ""
            row = self.store.one("SELECT vram FROM functions WHERE project_id=? AND name=?", proj["id"], old)
            engine = getattr(self, "native", None)
            if row is not None and row["vram"] is not None and engine is not None and engine.ida_ready():
                try:  # the database keeps the name too: the renamed function's address in IDA
                    if engine.ida_rename(proj["slug"], row["vram"], new):
                        engine.ida_save(proj["slug"])
                        ida_note = f" The IDA database now says {new}."
                    else:
                        ida_note = " (the IDA database refused the new name)"
                except Exception as exc:
                    ida_note = f" (the IDA database was not updated: {exc})"
            with self.store.tx() as db:  # the rows' display names follow in the same breath
                for r in db.execute("SELECT id, name FROM functions WHERE project_id=?",
                                    (proj["id"],)).fetchall():
                    renamed = apply_word_renames(r["name"] or "", words)
                    if renamed != (r["name"] or ""):
                        db.execute("UPDATE functions SET name=? WHERE id=?", (renamed, r["id"]))
            return (f"✅ renamed `{old}` -> `{new}` in {len(changed)} header(s) and in {len(rewritten)} matched "
                    f"sources; all still match.{ida_note} See the exact render with get_context(function=…).")
        raise NetworkError("headers are being edited heavily right now; retry")

    def adopt_renames(self, proj, renames: dict[str, str], message: str = "database sync") -> dict:
        """Whole-word renames discovered in the database, applied to everything dcore holds as
        text: stored headers (one new version per changed unit) and the matched/open sources.
        No gate and no IDA mirror — the database is where these names came from, and the caller
        re-checks any match the new environment actually breaks."""
        words = rename_words(renames)
        if not words:
            return {"headers": 0, "sources": 0}
        scanning = {""} | self._stored_units(proj["id"])
        changed: dict[str, str] = {}
        for u in scanning:
            ctx = self._context(proj["id"], u)
            text = apply_word_renames(ctx["header"], words)
            if text != ctx["header"]:
                changed[u] = text
        n_src = 0
        with self.store.tx() as db:
            for u, header in changed.items():
                version = self._next_version(db, proj["id"])
                db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                           "VALUES(?,?,?,?,?,?,?)",
                           (proj["id"], version, header, None, message, time.time(), u))
            for r in db.execute("SELECT id, matched_source FROM functions WHERE project_id=? AND status='matched'",
                                (proj["id"],)).fetchall():
                src = r["matched_source"] or ""
                new_src = apply_word_renames(src, words)
                if new_src != src:
                    db.execute("UPDATE functions SET matched_source=?, best_source=? WHERE id=?",
                               (new_src, new_src, r["id"]))
                    n_src += 1
            for r in db.execute("SELECT id, best_source FROM functions WHERE project_id=? AND status='open' "
                                "AND best_source IS NOT NULL", (proj["id"],)).fetchall():
                src = r["best_source"] or ""
                new_src = apply_word_renames(src, words)
                if new_src != src:
                    db.execute("UPDATE functions SET best_source=? WHERE id=?", (new_src, r["id"]))
            if changed:
                self._event(db, proj["id"], None, "context",
                            f"{message}: {len(changed)} header(s), {n_src} source(s)")
        return {"headers": len(changed), "sources": n_src}

    def _latest_version(self, db, project_id: int, unit: str) -> int | None:
        row = db.execute("SELECT MAX(version) AS v FROM context_versions WHERE project_id=? AND unit=?",
                         (project_id, unit)).fetchone()
        return row["v"]

    def _next_version(self, db, project_id: int) -> int:
        return (db.execute("SELECT MAX(version) AS v FROM context_versions WHERE project_id=?",
                           (project_id,)).fetchone()["v"] or 0) + 1

    def _matched_using(self, proj, unit: str) -> list:
        units = self._unit_contexts(proj["id"])
        return [f for f in self.store.all("SELECT * FROM functions WHERE project_id=? AND status='matched'", proj["id"])
                if self._effective_unit(f, units) == unit]

    def regression_test(self, proj, header: str | None, sources: dict[int, str] | None = None,
                        only: list | None = None, header_for=None) -> list[tuple[str, str]]:
        matched = only if only is not None else self.store.all(
            "SELECT * FROM functions WHERE project_id=? AND status='matched'", proj["id"])

        def check(fn) -> tuple[str, str] | None:
            res = self._compile(proj, header_for(fn) if header_for else header,
                                (sources or {}).get(fn["id"], fn["matched_source"]), fn=fn)
            if not res.ok:
                lines = [ln.strip() for ln in (res.log or "").splitlines() if ln.strip()]
                # the first line is the source file name; the first *error* is what the agent needs
                err = next((ln for ln in lines if "error" in ln.lower()), lines[0] if lines else "")
                return fn["name"], "no longer compiles: " + (err[:240] or "the compiler refused it")
            cand, verdict, _ = self._evaluate(fn, proj, res.obj)
            if verdict is None and cand is not None:
                want = fn["fingerprint"] if self._hash_only(fn) else self._target_obj(fn, proj).fingerprint()
                verdict = cand.fingerprint() == want
            if cand is None or not verdict:
                return fn["name"], "compiles but no longer matches"
            return None

        if not matched:  # nothing to protect, but the header must at least parse
            if header is None:
                return []
            from . import interfaces  # what a compile actually consumes: the stored block is always
            res = self._compile(proj, interfaces.strip_types(header), "")  # stripped and regenerated
            return [] if res.ok else [("<header>", res.log.strip()[:300])]
        return [b for b in self._pool.map(check, matched) if b]

    # ------------------------------------------------------------------ notes

    def add_note(self, agent: Agent, project: str | None, text: str, function: str | None = None) -> str:
        proj = self._project(project)
        fn = self._function(function, proj["slug"]) if function else None
        if not text.strip():
            raise NetworkError("empty note")
        with self.store.tx() as db:
            db.execute("INSERT INTO notes(project_id,function_id,agent_id,text,created_at) VALUES(?,?,?,?,?)",
                       (proj["id"], fn["id"] if fn else None, agent.id, text.strip()[:4000], time.time()))
        return "Noted. Other agents will see it" + (f" when they open {fn['name']}." if fn else " in their briefings.")

    def search_notes(self, project: str | None, query: str) -> str:
        proj = self._project(project)
        rows = self.store.all(
            "SELECT n.text, n.created_at, a.name AS agent, f.name AS fn FROM notes n "
            "LEFT JOIN agents a ON a.id=n.agent_id LEFT JOIN functions f ON f.id=n.function_id "
            "WHERE n.project_id=? AND n.text LIKE ? ORDER BY n.id DESC LIMIT 20", proj["id"], f"%{query}%")
        if not rows:
            return f"No notes matching {query!r}."
        return "\n".join(f"- [{r['fn'] or 'project'}] ({r['agent']}, {_ago(r['created_at'])}) {r['text']}" for r in rows)

    def report_issue(self, agent: Agent, project: str | None, kind: str, title: str,
                     detail: str = "", function: str | None = None) -> str:
        """The automated todo list: agents file what they cannot work around — a tool bug or a
        missing capability — as a structured item. Identical titles merge (hit counter), so the list
        stays short and the recurring walls sort to the top."""
        kind = (kind or "").strip().lower()
        if kind not in ("bug", "need"):
            raise NetworkError("report kind must be 'bug' (something in the stack misbehaves or cannot be "
                               "worked around) or 'need' (a capability that is missing)")
        title = " ".join((title or "").split())
        if not title:
            raise NetworkError("a report needs a one-line title")
        proj = self._project(project)
        fn = self._function(function, proj["slug"]) if function else None
        now = time.time()
        with self.store.tx() as db:
            row = db.execute("SELECT id, hits FROM reports WHERE project_id=? AND kind=? AND title=?",
                             (proj["id"], kind, title)).fetchone()
            if row:
                db.execute("UPDATE reports SET hits=hits+1, last_seen=?, detail=COALESCE(detail, ?), "
                           "function=COALESCE(function, ?) WHERE id=?",
                           (now, (detail or "").strip()[:4000] or None, fn["name"] if fn else None, row["id"]))
                report_id, hits = row["id"], row["hits"] + 1
            else:
                cur = db.execute("INSERT INTO reports(project_id,kind,title,detail,function,agent_id,"
                                 "created_at,last_seen) VALUES(?,?,?,?,?,?,?,?)",
                                 (proj["id"], kind, title, (detail or "").strip()[:4000],
                                  fn["name"] if fn else None, agent.id, now, now))
                report_id, hits = cur.lastrowid, 1
            self._event(db, proj["id"], agent.id, "report",
                        f"{kind}: {title}" + (f" ({fn['name']})" if fn else ""))
        suffix = (f" (seen {hits} times — it's on the todo list)" if hits > 1 else " — it's on the todo list")
        return f"✅ report #{report_id} {kind}: {title}{suffix}"

    def reports(self, project: str | None) -> list[dict]:
        """The open todo items for a project (most-hit first)."""
        proj = self._project(project)
        rows = self.store.all(
            "SELECT r.id, r.kind, r.title, r.detail, r.function, r.hits, r.created_at, r.last_seen, "
            "a.name AS agent FROM reports r LEFT JOIN agents a ON a.id=r.agent_id "
            "WHERE r.project_id=? AND r.status='open' ORDER BY r.hits DESC, r.last_seen DESC", proj["id"])
        return [dict(r) for r in rows]

    # ----------------------------------------------------------------- status

    def status_json(self) -> dict:
        with self.store.tx() as db:
            self._expire_claims(db)
        projects = []
        for p in self.store.all("SELECT * FROM projects ORDER BY slug"):
            rows = self.store.all(
                "SELECT name, n_insns, status, best_score, size, attempts, meta, mode FROM functions "
                "WHERE project_id=? ORDER BY name", p["id"])
            decomp = [f for f in rows if function_mode(f) == "decompile"]
            header_only = sum(1 for f in rows if function_mode(f) == "header")
            skipped = sum(1 for f in rows if function_mode(f) == "skip")
            claims = self.store.all(
                "SELECT f.name, a.name AS agent, c.claimed_at, f.best_score, f.n_insns FROM claims c "
                "JOIN functions f ON f.id=c.function_id JOIN agents a ON a.id=c.agent_id "
                "WHERE f.project_id=? ORDER BY c.claimed_at", p["id"])
            ctx = self._context(p["id"])
            claimed = {c["name"] for c in claims}
            funcs = [{"name": f["name"], "insns": f["n_insns"], "best": f["best_score"],
                      "mode": function_mode(f),
                      "status": "matched" if f["status"] == "matched" else "claimed" if f["name"] in claimed else "open"}
                     for f in rows]
            legal = json.loads(p["config"]).get("legal", {})
            projects.append({
                "legal": {"basis": legal.get("basis"), "license": legal.get("license")},
                "funcs": funcs,
                "slug": p["slug"], "name": p["name"], "arch": p["arch"], "description": p["description"],
                "functions": len(decomp),
                "header_functions": header_only, "skipped_functions": skipped,
                "matched": sum(1 for f in decomp if f["status"] == "matched"),
                "bytes": sum(int(f["size"] or 0) for f in decomp),
                "matched_bytes": sum(int(f["size"] or 0) for f in decomp if f["status"] == "matched"),
                "attempts": sum(int(f["attempts"] or 0) for f in decomp),
                "context_version": ctx["version"] if ctx else 0,
                "claims": [{"function": c["name"], "agent": c["agent"], "since": c["claimed_at"],
                            "best_score": c["best_score"], "insns": c["n_insns"]} for c in claims],
            })
        leaders = self.store.all(
            "SELECT a.name, a.owner, COUNT(f.id) AS matches, COALESCE(SUM(f.n_insns),0) AS insns, a.last_seen "
            "FROM agents a LEFT JOIN functions f ON f.matched_agent_id=a.id "
            "GROUP BY a.id ORDER BY insns DESC, matches DESC LIMIT 25")
        events = self.store.all(
            "SELECT e.kind, e.detail, e.created_at, a.name AS agent, p.slug FROM events e "
            "LEFT JOIN agents a ON a.id=e.agent_id LEFT JOIN projects p ON p.id=e.project_id "
            "ORDER BY e.id DESC LIMIT 30")
        return {
            "projects": projects,
            "leaderboard": [dict(r) for r in leaders],
            "events": [dict(r) for r in events],
        }

    def status(self, agent: Agent | None = None) -> str:
        s = self.status_json()
        out = []
        for p in s["projects"]:
            pct = 100 * p["matched_bytes"] / (p["bytes"] or 1)
            out.append(f"{p['slug']}: {p['matched']}/{p['functions']} functions, {pct:.1f}% of code matched, "
                       f"context.h v{p['context_version']}, {len(p['claims'])} agents working")
            out += [f"  - {c['agent']} on {c['function']} ({c['insns']} insns, best {c['best_score']})"
                    for c in p["claims"]]
        out.append("Leaderboard (instructions matched):")
        out += [f"  {i + 1}. {r['name']}{' (you)' if agent and r['name'] == agent.name else ''}: "
                f"{r['matches']} functions / {r['insns']} insns" for i, r in enumerate(s["leaderboard"][:10])]
        return "\n".join(out)

    # ------------------------------------------------------------- moderation
    # Operator-only actions (CLI), for takedown requests and GDPR erasure requests.

    def remove_project(self, slug: str) -> int:
        proj = self._project(slug)
        with self.store.tx() as db:
            ids = [r["id"] for r in db.execute("SELECT id FROM functions WHERE project_id=?", (proj["id"],))]
            for table in ("claims", "attempts"):
                db.executemany(f"DELETE FROM {table} WHERE function_id=?", [(i,) for i in ids])
            for table in ("notes", "events", "context_versions", "functions"):
                db.execute(f"DELETE FROM {table} WHERE project_id=?", (proj["id"],))
            db.execute("DELETE FROM projects WHERE id=?", (proj["id"],))
        return len(ids)

    def reset_function(self, slug: str, name: str) -> None:
        """Remove every submission for one function (matched source, attempts, notes) and reopen it."""
        fn = self._function(name, slug)
        with self.store.tx() as db:
            for table in ("claims", "attempts", "notes"):
                db.execute(f"DELETE FROM {table} WHERE function_id=?", (fn["id"],))
            db.execute("UPDATE functions SET status='open', best_score=NULL, best_source=NULL, best_agent_id=NULL, "
                       "matched_source=NULL, matched_agent_id=NULL, matched_at=NULL, attempts=0, abandons=0 "
                       "WHERE id=?", (fn["id"],))

    def revoke_agent(self, name: str, erase: bool = False) -> None:
        """Disable an agent's token. With erase=True also strip its identity (GDPR erasure):
        the agent is renamed to an anonymous id and the operator name is removed."""
        row = self.store.one("SELECT id FROM agents WHERE name=?", name)
        if row is None:
            raise NetworkError(f"no agent named {name!r}")
        with self.store.tx() as db:
            db.execute("DELETE FROM claims WHERE agent_id=?", (row["id"],))
            db.execute("UPDATE agents SET token_hash=? WHERE id=?", ("revoked:" + secrets.token_hex(16), row["id"]))
            if erase:
                db.execute("UPDATE agents SET name=?, owner=NULL WHERE id=?", (f"erased-{row['id']}", row["id"]))

    def list_notes(self, slug: str) -> list[dict]:
        proj = self._project(slug)
        return [dict(r) for r in self.store.all(
            "SELECT n.id, f.name AS function, a.name AS agent, n.text FROM notes n LEFT JOIN functions f "
            "ON f.id=n.function_id LEFT JOIN agents a ON a.id=n.agent_id WHERE n.project_id=? ORDER BY n.id",
            proj["id"])]

    def delete_note(self, note_id: int) -> None:
        with self.store.tx() as db:
            if db.execute("DELETE FROM notes WHERE id=?", (note_id,)).rowcount == 0:
                raise NetworkError(f"no note with id {note_id}")

    # ----------------------------------------------------------------- export

    def export(self, project: str, out_dir: Path) -> int:
        """Write matched sources + the current context as a tree you can PR upstream."""
        proj = self._project(project)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "context.h").write_text(self._context(proj["id"])["header"], encoding="utf-8")
        for unit in sorted(self._unit_contexts(proj["id"])):
            (out_dir / "contexts").mkdir(exist_ok=True)
            (out_dir / "contexts" / f"{unit}.h").write_text(self._context(proj["id"], unit)["header"], encoding="utf-8")
        rows = self.store.all(
            "SELECT f.name, f.matched_source, a.name AS agent, a.owner FROM functions f "
            "LEFT JOIN agents a ON a.id=f.matched_agent_id WHERE f.project_id=? AND f.status='matched' "
            "ORDER BY f.name", proj["id"])
        (out_dir / "src").mkdir(exist_ok=True)
        credits = []
        for r in rows:
            (out_dir / "src" / f"{r['name']}.c").write_text(
                f'#include "context.h"\n\n// matched by {r["agent"]}' + (f" (operator: {r['owner']})" if r["owner"] else "")
                + f"\n{r['matched_source'].strip()}\n", encoding="utf-8")
            credits.append(f"{r['name']}\t{r['agent']}\t{r['owner'] or ''}")
        (out_dir / "CREDITS.tsv").write_text("function\tagent\toperator\n" + "\n".join(credits) + "\n",
                                             encoding="utf-8")
        return len(rows)
