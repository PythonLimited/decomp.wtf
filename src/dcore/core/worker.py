"""Donated-compute worker: claim a job, run an external solver, submit through the same judge.

The solver protocol is intentionally small: JSON on stdin, replacement function source on stdout.
The worker writes `job.json`, `context.h`, and the provided include files into a temporary
directory so a solver can use a normal compiler if it needs one.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from . import jobs
from .network import Network, NetworkError


class WorkerError(RuntimeError):
    pass


def run_solver(command: str, job: dict, timeout: float = 300.0) -> str:
    """Run one solver invocation and return the replacement source it prints."""
    if not command.strip():
        raise WorkerError("no solver command configured")
    with tempfile.TemporaryDirectory(prefix="dcore-worker-") as tmp:
        root = Path(tmp)
        for name, text in (job.get("include_files") or {}).items():
            rel = Path(name)
            if rel.is_absolute() or ".." in rel.parts:
                continue
            dest = root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8", errors="replace")
        (root / "context.h").write_text(job.get("context") or "", encoding="utf-8")
        payload = json.dumps(job)
        (root / "job.json").write_text(payload, encoding="utf-8")
        try:
            proc = subprocess.run(command, shell=True, cwd=root, input=payload, text=True,
                                  capture_output=True, timeout=max(1.0, timeout))
        except subprocess.TimeoutExpired:
            raise WorkerError(f"solver timed out after {int(timeout)}s") from None
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        raise WorkerError(f"solver exited {proc.returncode}" + (f": {detail[-1]}" if detail else ""))
    source = (proc.stdout or "").strip()
    if not source:
        raise WorkerError("solver printed no source")
    return source


def release_claim(net: Network, agent, function: str, project: str | None = None) -> None:
    fn = net._function(function, project)
    with net.store.tx() as db:
        db.execute("DELETE FROM claims WHERE function_id=? AND agent_id=?", (fn["id"], agent.id))


def claim(net: Network, agent, project: str | None = None,
          function: str | None = None) -> dict | None:
    """Pick and atomically claim one job; None when the queue is empty."""
    job = jobs.next_job(net, agent, project, function)
    if job is None:
        return None
    net.claim_row(agent, project, function=job["function"])
    return job


def submit(net: Network, agent, project: str, function: str, source: str) -> dict:
    return jobs.submit(net, agent, project, function, source)


def _post(url: str, token: str, path: str, payload: dict, timeout: float = 60.0) -> dict:
    req = urllib.request.Request(
        url.rstrip("/") + path, method="POST", data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read() or b"{}").get("error")
        except ValueError:
            detail = None
        raise WorkerError(detail or f"HTTP {e.code}") from None
    except (OSError, ValueError) as e:
        raise WorkerError(str(e)) from None


def run_remote(url: str, token: str, *, command: str, project: str | None = None,
               function: str | None = None, count: int = 1, timeout: float = 300.0, log=print) -> dict:
    """HTTP worker: the coordinator owns the DB and compiler, this process only runs the solver."""
    stats = {"attempted": 0, "matched": 0, "rejected": 0, "no_jobs": False}
    while count <= 0 or stats["attempted"] < count:
        data = _post(url, token, "/api/worker/claim", {"project": project, "function": function})
        job = data.get("job")
        if not job:
            stats["no_jobs"] = True
            log("no jobs available")
            break
        stats["attempted"] += 1
        try:
            source = run_solver(command, job, timeout=timeout)
        except WorkerError as e:
            try:
                _post(url, token, "/api/worker/release",
                      {"project": job["project"], "function": job["function"]})
            except WorkerError:
                pass
            stats["rejected"] += 1
            log(f"{job['function']}: {e}")
            continue
        try:
            result = _post(url, token, "/api/worker/submit",
                           {"project": job["project"], "function": job["function"], "source": source})
        except WorkerError as e:
            stats["rejected"] += 1
            log(f"{job['function']}: submit failed: {e}")
            try:
                _post(url, token, "/api/worker/release",
                      {"project": job["project"], "function": job["function"]})
            except WorkerError:
                pass
            continue
        if result.get("accepted") and result.get("matched"):
            stats["matched"] += 1
            log(f"{job['function']}: matched")
        else:
            stats["rejected"] += 1
            log(f"{job['function']}: rejected: {result.get('reason') or result.get('problems') or result.get('score')}")
            try:
                _post(url, token, "/api/worker/release",
                      {"project": job["project"], "function": job["function"]})
            except WorkerError:
                pass
    return stats


def run_worker(net: Network, agent, *, command: str, project: str | None = None,
               function: str | None = None, count: int = 1, timeout: float = 300.0, log=print) -> dict:
    """Claim/submit until `count` attempts (0 = until no jobs remain)."""
    stats = {"attempted": 0, "matched": 0, "rejected": 0, "no_jobs": False}
    claim_errors = 0
    while count <= 0 or stats["attempted"] < count:
        try:
            job = claim(net, agent, project, function)
        except NetworkError as e:
            claim_errors += 1
            log(f"claim failed: {e}")
            if claim_errors >= 3:
                break
            continue
        if job is None:
            stats["no_jobs"] = True
            log("no jobs available")
            break
        stats["attempted"] += 1
        try:
            source = run_solver(command, job, timeout=timeout)
        except WorkerError as e:
            release_claim(net, agent, job["function"], job["project"])
            stats["rejected"] += 1
            log(f"{job['function']}: {e}")
            continue
        result = jobs.submit(net, agent, job["project"], job["function"], source)
        if result.get("accepted") and result.get("matched"):
            stats["matched"] += 1
            log(f"{job['function']}: matched")
        else:
            stats["rejected"] += 1
            log(f"{job['function']}: rejected: {result.get('reason') or result.get('problems') or result.get('score')}")
        release_claim(net, agent, job["function"], job["project"])
    return stats
