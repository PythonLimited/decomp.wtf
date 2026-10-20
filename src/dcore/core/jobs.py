"""Donated compute, coordinator side.

Volunteers run `dcore worker` on their own machines: it fetches a near-matching function, searches
for a better C variant locally, and submits improvements. The coordinator recompiles everything it
receives with its own pinned toolchain, so a worker cannot fake a result; it only donates search time.

Only projects with a pinned toolchain and full targets take part (never hash-only projects), so every
byte handed to a worker belongs to a project whose code may lawfully be shared.
"""

from __future__ import annotations

import base64
import json
import random
from pathlib import Path

from ..targets import plat_pack
from . import scoring
from .network import Agent, Network, NetworkError

MAX_INCLUDE_BYTES = 256 * 1024


def next_job(net: Network, agent: Agent, project: str | None = None,
             function: str | None = None) -> dict | None:
    sql = """SELECT f.*, p.slug, p.config, p.root, p.arch, p.big_endian FROM functions f
             JOIN projects p ON p.id = f.project_id
             WHERE f.status = 'open' AND f.mode = 'decompile'
               AND f.best_score > 0 AND f.target IS NOT NULL AND f.best_source IS NOT NULL
               AND f.id NOT IN (SELECT function_id FROM claims)"""
    params: list = []
    if project:
        sql += " AND p.slug = ?"
        params.append(project)
    if function:
        sql += " AND f.name = ?"
        params.append(function)
    sql += " ORDER BY CAST(f.best_score AS REAL) / (f.n_insns * 100) ASC LIMIT 12"
    rows = net.store.all(sql, *params)
    rows = [r for r in rows if (json.loads(r["config"]).get("compiler", {}).get("toolchain")
                                 or json.loads(r["config"]).get("compiler", {}).get("image"))]
    if not rows:
        return None
    fn = random.choice(rows[:4])  # spread workers over the closest few
    cfg = json.loads(fn["config"])["compiler"]
    includes, total = {}, 0
    for d in cfg.get("include_dirs", []):
        base = (Path(fn["root"]) / d).resolve()
        for f in sorted(base.rglob("*")):
            if f.is_file():
                total += f.stat().st_size
                if total > MAX_INCLUDE_BYTES:
                    break
                includes[str(f.relative_to(base))] = f.read_text(errors="replace", encoding="utf-8")
    code = net._ensure_row_code(fn, fn) or b""  # jobs rows carry the project columns too
    return {
        "project": fn["slug"], "function": fn["name"], "unit": fn["unit"] or None,
        "toolchain": cfg.get("toolchain") or cfg.get("image") or "", "flags": cfg.get("flags"), "cmd": cfg.get("cmd"),
        "context": net._context(fn["project_id"], fn["unit"])["header"],
        "include_files": includes,
        "source": fn["best_source"], "best_score": fn["best_score"], "max_score": fn["n_insns"] * 100,
        "target": {"arch": fn["arch"], "big_endian": bool(fn["big_endian"]),
                   "code": base64.b64encode(code).decode(), "relocs": json.loads(fn["relocs"])},
    }


def submit(net: Network, agent: Agent, project: str, function: str, source: str) -> dict:
    net._require_budget(agent)
    fn = net._function(function, project)
    if fn["status"] == "matched":
        return {"accepted": False, "reason": "already matched"}
    if net._hash_only(fn):
        raise NetworkError("hash-only projects don't take donated compute")
    claim = net.store.one("SELECT agent_id FROM claims WHERE function_id=?", fn["id"])
    if claim and claim["agent_id"] != agent.id:
        return {"accepted": False, "reason": "an agent is working on it right now"}
    proj = net.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
    ctx = net._context(proj["id"], fn["unit"])
    native = getattr(net, "native", None) if getattr(net, "native_slug", lambda _s: None)(proj["slug"]) else None
    if native is not None:
        # Donated compute is a final submission: same function-only fence, same pinned compiler
        # and the same resolved-reference judge as compile_and_diff. A worker only donates search.
        try:
            native.refuse_extra_content(source, fn["name"])
        except NetworkError as e:
            return {"accepted": False, "reason": str(e)}
        res = native.compile_fn(fn, proj, ctx["header"], source)
        cand, verdict, problems = (None, None, [])
        if res.ok:
            cand, verdict, problems = native.judge(fn, proj, res.obj)
        if not res.ok or cand is None:
            net._record(fn, agent, None, source, ctx["version"], via="permuter")
            return {"accepted": False, "reason": "did not compile on the coordinator"}
        before = fn["best_score"]
        score = verdict.score if verdict is not None else 100
        matched = bool(verdict and verdict.match)
        net._record(fn, agent, score, source, ctx["version"], matched=matched, via="permuter")
        if matched:
            net.add_note(agent, proj["slug"], "matched by donated compute (permuter)", fn["name"])
        return {"accepted": True, "score": score, "improved": before is None or score < before,
                "matched": matched, "problems": problems[:3]}
    res = net._compile(proj, ctx["header"], source)
    cand = plat_pack(net.cfg(proj).get("format") or "elf").object_reader().extract_function(res.obj, fn["name"]) if res.ok else None
    if cand is None:
        net._record(fn, agent, None, source, ctx["version"], via="permuter")
        return {"accepted": False, "reason": "did not compile on the coordinator"}
    d = scoring.diff(net._target_obj(fn, proj), cand)
    before = fn["best_score"]
    net._record(fn, agent, d.score, source, ctx["version"], matched=d.bytes_match, via="permuter")
    if d.bytes_match:
        net.add_note(agent, proj["slug"], "matched by donated compute (permuter)", fn["name"])
    return {"accepted": True, "score": d.score, "improved": before is None or d.score < before,
            "matched": d.bytes_match}
