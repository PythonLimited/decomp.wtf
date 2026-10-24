"""The local decomp.wtf server: the GUI, its API, and the MCP endpoint agents connect to.

It listens on 127.0.0.1 only. The GUI needs a per-launch secret (handed to the browser in the URL the
app opens, then kept in a same-site cookie); agents need their own bearer token. Host headers are
checked on every request, so web pages can't reach it through DNS rebinding.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import mimetypes
import re
import os
import secrets
import shlex
import shutil
import subprocess
import sys
import threading
import time
import traceback
import uuid
from importlib import resources
from pathlib import Path

import anyio
from mcp.server.mcpserver import Context
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .. import __version__
from ..core import hostenv
from ..core.network import NetworkError
from ..core import worker as core_worker
from . import agents, chat, connect, tools
from ..core.engine import PLATFORM_STATUS, Engine
from ..targets.image import NativeError

COOKIE = "decomp_live"
MAX_DISC = 16 * 1024 * 1024 * 1024  # dual-layer DVD and then some


def file_log(path: Path) -> logging.Logger:
    """decomp.wtf's own log (logs/decomp.log in its data folder): every job, what it said, and every error with its
    traceback, so a failed import can be reported with the whole story."""
    logger = logging.getLogger("decomp.wtf")
    if not any(getattr(h, "baseFilename", None) == str(path) for h in logger.handlers):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.handlers.RotatingFileHandler(path, maxBytes=2 << 20, backupCount=2, encoding="utf-8")
        except OSError:
            return logger
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


def _tool_of(cmd) -> str:
    """The program a command ran (past a systemd-run wrapper), by name."""
    argv = [str(a) for a in cmd] if isinstance(cmd, (list, tuple)) else str(cmd).split()
    if "--" in argv and Path(argv[0]).name.startswith("systemd-run"):
        argv = argv[argv.index("--") + 1:]
    return Path(argv[0]).name if argv else "a tool"


def job_error(e: BaseException, log_path: Path | None = None) -> str:
    """What to tell the user when a job fails: why, in words, for every kind of failure."""
    if isinstance(e, subprocess.TimeoutExpired):
        mins = max(1, round((e.timeout or 0) / 60))
        return (f"{_tool_of(e.cmd)} took longer than {mins} minute{'s' if mins != 1 else ''} and was stopped. "
                "A very big game can need more: please report it, with the log")
    if isinstance(e, subprocess.CalledProcessError):
        said = e.stderr or e.output or ""  # what the command said, so the error shows why
        said = (said.decode("utf-8", "replace") if isinstance(said, bytes) else said).strip()
        return f"{_tool_of(e.cmd)} failed ({e.returncode})" + (f": {said[-400:]}" if said else "")
    if isinstance(e, MemoryError):
        return "this computer ran out of memory: close other programs and try again"
    if isinstance(e, (NetworkError, NativeError, ValueError, RuntimeError, OSError)):
        return str(e) or type(e).__name__
    where = f" (the log: {hostenv.shown_path(log_path)})" if log_path else ""
    return (f"something went wrong inside decomp.wtf ({type(e).__name__}: {e}). That's a bug: please report it with "
            f"the log{where}")


class Jobs:
    """Background work the GUI can follow: imports and installs. A job always ends: done, or an error that says why
    (never `running` forever because of an error nobody caught). Everything goes to the log file too."""

    def __init__(self, log_path: Path | None = None):
        self.jobs: dict[str, dict] = {}
        self.log_path = log_path
        self.logger = file_log(log_path) if log_path else logging.getLogger("decomp.wtf")

    def start(self, kind: str, fn) -> str:
        jid = uuid.uuid4().hex[:12]
        job = {"id": jid, "kind": kind, "state": "running", "log": [], "result": None, "error": None, "t": time.time()}
        self.jobs[jid] = job
        logger = self.logger
        logger.info("job %s %s started", kind, jid)

        def log(line: str) -> None:
            job["log"].append(str(line))
            logger.info("[%s %s] %s", kind, jid[:6], line)

        def run():
            try:
                job["result"] = fn(log)
                job["state"] = "done"
                logger.info("job %s %s done in %.0fs", kind, jid, time.time() - job["t"])
            except BaseException as e:  # noqa: BLE001: a job must end, whatever went wrong
                if getattr(e, "details", None):  # what the tool said, in full
                    job["trace"] = str(e.details)[-6000:]
                elif not isinstance(e, (NetworkError, NativeError, ValueError)):
                    job["trace"] = traceback.format_exc()[-4000:]
                job["error"] = job_error(e, self.log_path)
                job["state"] = "error"  # last: whoever sees the state sees the rest
                logger.error("job %s %s failed: %s\n%s", kind, jid, job["error"], traceback.format_exc())
                if isinstance(e, (KeyboardInterrupt, SystemExit)):
                    raise
        threading.Thread(target=run, daemon=True, name=f"job-{kind}").start()
        return jid


class Settings:
    def __init__(self, path: Path):
        self.path = path
        try:
            self.data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.data = {}
        if not isinstance(self.data.get("endpoints"), list):  # one saved "api" before 0.10.1: the first endpoint
            old = self.data.get("api") if isinstance(self.data.get("api"), dict) else {}
            self.data["endpoints"] = [agents.endpoint_entry(old | {"id": "e1"})] if old.get("base_url") or old.get("provider") else []

    def save(self) -> None:
        self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # -- API endpoints: OpenAI-compatible servers for the built-in agent, each with its own address, model and key

    def endpoints(self) -> list[dict]:
        return [e for e in self.data.get("endpoints") or [] if isinstance(e, dict) and e.get("id")]

    def endpoint(self, eid: str) -> dict | None:
        return next((e for e in self.endpoints() if e["id"] == eid), None)

    def save_endpoint(self, data: dict) -> dict:
        """Add an endpoint (no id) or change one. A key is only replaced by a new one typed in (the masked one the
        GUI shows comes back unchanged)."""
        numbers = {}
        for k in ("context_tokens", "max_sessions"):  # the model's context in tokens (empty = find out); a box's limit
            if k in data:
                try:
                    numbers[k] = int(str(data[k] or "").strip() or 0)
                except ValueError:
                    raise ValueError("the context size is a number of tokens, like 16384" if k == "context_tokens"
                                     else "the session limit is a number, like 1") from None
        current = self.endpoint(str(data.get("id") or ""))
        if current is None:  # ids are never reused: a session resumed later can't end up on another machine
            ids = {e["id"] for e in self.endpoints()}
            n = max(int(self.data.get("endpoint_seq") or 0), len(ids)) + 1
            while f"e{n}" in ids:
                n += 1
            self.data["endpoint_seq"] = n
            current = {"id": f"e{n}"}
            self.data.setdefault("endpoints", []).append(current)
        for k in ("name", "provider", "base_url", "model"):
            if k in data:
                current[k] = str(data[k] or "").strip()
        for k, n in numbers.items():
            if n:
                current[k] = max(2048, n) if k == "context_tokens" else max(1, min(n, 32))
            else:
                current.pop(k, None)
        if data.get("api_key") and "•" not in str(data["api_key"]):
            current["api_key"] = str(data["api_key"]).strip()
        if data.get("clear_key"):
            current.pop("api_key", None)
        current.update(agents.endpoint_entry(current))
        return current

    def remove_endpoint(self, eid: str) -> None:
        self.data["endpoints"] = [e for e in self.endpoints() if e["id"] != eid]

    def public(self) -> dict:
        def masked(e: dict) -> dict:
            out = {k: v for k, v in e.items() if k != "api_key"}
            if e.get("api_key"):
                out["api_key"], out["has_key"] = "•" * 8 + e["api_key"][-4:], True
            return out

        eps = [masked(e) for e in self.endpoints()]
        return {"endpoints": eps, "api": eps[0] if eps else {},
                "per_session": self.data.get("per_session", agents.PER_SESSION), "last_project": self.data.get("last_project"),
                "autopilot": self.data.get("autopilot", True), "budget_usd": self.data.get("budget_usd") or 0,
                "auto_update": bool(self.data.get("auto_update")), "check_updates": self.data.get("check_updates", True) is not False,
                "launcher": _launcher(self.data.get("launcher") or {}), "recent_models": self.data.get("recent_models") or {}}


def _session_options(entry: dict) -> dict:
    """What a built-in agent session needs from its endpoint."""
    out = {"endpoint": entry.get("id") or "", "provider": entry["provider"], "base_url": entry["base_url"],
           "model": entry["model"], "provider_name": entry["name"]}
    return out | {k: entry[k] for k in ("api_key", "context_tokens") if entry.get(k)}


def _spread(settings: Settings, manager, picked: list[str], count: int, given: dict) -> list[tuple[dict, int]]:
    """(endpoint, sessions) for a start of `count` built-in agent sessions: spread over the endpoints picked, one
    at a time in turn, each up to its own limit of sessions at once (a small box serves one request at a time).
    A start without endpoints (an older GUI, or an address typed in) uses the first saved one, with what it
    changes; a saved key only ever goes to its own endpoint's address."""
    if not picked:
        first = settings.endpoints()[0] if settings.endpoints() else {}
        typed = {k: v for k, v in given.items() if k in ("provider", "base_url", "model", "context_tokens") and v}
        entry = agents.endpoint_entry(first | typed)
        if first and entry["base_url"].rstrip("/") != first["base_url"].rstrip("/"):
            entry.pop("api_key", None)
        if not entry.get("base_url") or not entry.get("model"):
            raise ValueError("add an API endpoint first (Agents & models): its address and model")
        return [(entry, count)]
    eps = [settings.endpoint(e) for e in picked]
    if any(e is None for e in eps):
        raise ValueError("an endpoint you picked isn't saved any more: pick again")
    busy = {e["id"]: sum(1 for x in manager.sessions.values() if x.kind == "api" and x.options.get("endpoint") == e["id"]
                         and x.state in ("starting", "working", "waiting") and not x.stop.is_set()) for e in eps}
    plan = {e["id"]: 0 for e in eps}
    for _ in range(count):
        room = [e for e in eps if not e.get("max_sessions") or busy[e["id"]] + plan[e["id"]] < int(e["max_sessions"])]
        if not room:
            break
        pick = min(room, key=lambda e: (busy[e["id"]] + plan[e["id"]], eps.index(e)))
        plan[pick["id"]] += 1
    if not any(plan.values()):
        raise ValueError("every endpoint you picked already runs as many sessions as you allowed it")
    return [(e, plan[e["id"]]) for e in eps if plan[e["id"]]]


def _launcher(saved: dict) -> dict:
    """The last launcher choice; one saved for Gemini CLI (retired) comes back as Antigravity with its default model."""
    if saved.get("kind") and agents.kind_id(saved["kind"]) != saved["kind"]:
        return {**saved, "kind": agents.kind_id(saved["kind"]), "model": ""}
    return saved


def _static(name: str) -> bytes | None:
    if ".." in name or name.startswith(("/", "\\")):
        return None
    try:
        return resources.files("dcore.app").joinpath("static", name).read_bytes()
    except (FileNotFoundError, IsADirectoryError, OSError):
        return None


def build(net: Engine, home: Path, port: int, secret: str):
    mcp_url = f"http://127.0.0.1:{port}/mcp"
    build_id = ""  # a source install tracks no build id
    manager = agents.Manager(net, home, mcp_url)
    jobs = Jobs(home / "logs" / "decomp.log")
    settings = Settings(home / "settings.json")
    manager.budget = lambda: float(settings.data.get("budget_usd") or 0)

    def remember(running: list[dict]) -> None:
        settings.data["running_agents"] = running
        settings.save()
    manager.persist = remember
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    def agent_of(ctx: Context):
        headers = ctx.headers or {}
        auth = headers.get("authorization") or headers.get("Authorization") or ""
        agent = net.authenticate(auth.removeprefix("Bearer ").strip() or None)
        slug = manager.project_of(agent.id) or settings.data.get("last_project")
        if not slug:
            raise NetworkError("no project is open in decomp.wtf; open a ROM in the app first")
        return agent, slug

    # helpers that were working when the app last stopped carry on
    resume = [r for r in settings.data.get("running_agents", []) if isinstance(r, dict)]
    for r in resume:
        try:
            net.project_row(r["slug"])
            options = dict(r.get("options") or {})
            if r["kind"] == "api":
                saved = settings.endpoint(str(options.get("endpoint") or "")) if options.get("endpoint") else (
                    next((e for e in settings.endpoints() if e["base_url"] == options.get("base_url")), None))
                if saved is None and options.get("endpoint"):
                    continue  # its endpoint was removed since
                if saved is not None:  # as the endpoint is now, with its key
                    options.update(_session_options(saved))
            manager.start(r["kind"], r["slug"], 1, options)
        except (NetworkError, ValueError, KeyError):
            continue

    mcp = tools.build_mcp(net, agent_of)
    chat.register(mcp, net, manager, jobs, settings, port, secret)

    # Each agent sees the tools for its job: the agent you talk to sees everything; a helper only the work tools
    # for its project's kind (fewer tool definitions in every request, nothing it shouldn't call).
    from mcp_types import ListToolsResult, PaginatedRequestParams

    async def scoped_tools(ctx, params):
        everything = await mcp.list_tools()
        auth = (getattr(ctx.request, "headers", None) or {}).get("authorization", "")
        try:
            agent = net.authenticate(auth.removeprefix("Bearer ").strip() or None)
        except NetworkError:
            return ListToolsResult(tools=everything)
        if net.is_chat(agent):
            return ListToolsResult(tools=everything)
        slug = manager.project_of(agent.id) or settings.data.get("last_project")
        keep = set(tools.tool_names(bool(slug and net.native_slug(slug))))
        return ListToolsResult(tools=[t for t in everything if t.name in keep])

    mcp._lowlevel_server.add_request_handler("tools/list", PaginatedRequestParams, scoped_tools)

    def guard(request: Request, write: bool = False) -> Response | None:
        if request.headers.get("host") not in allowed_hosts:
            return JSONResponse({"error": "bad host"}, status_code=403)
        if not secrets.compare_digest(request.cookies.get(COOKIE, ""), secret):
            return JSONResponse({"error": "open decomp.wtf from the app or the `decomp` command"}, status_code=401)
        if write and request.headers.get("x-decomp") != "1":
            return JSONResponse({"error": "missing header"}, status_code=403)
        return None

    async def body(request: Request) -> dict:
        try:
            data = await request.json()
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}

    async def call(fn, *args):
        return await anyio.to_thread.run_sync(fn, *args)

    def fail(e: Exception, code: int = 400) -> JSONResponse:
        return JSONResponse({"error": str(e)}, status_code=code)

    # ------------------------------------------------------------------ pages

    @mcp.custom_route("/", methods=["GET"])
    async def index(request: Request) -> Response:
        if request.headers.get("host") not in allowed_hosts:
            return JSONResponse({"error": "bad host"}, status_code=403)
        key = request.query_params.get("k")
        if key:
            if not secrets.compare_digest(key, secret):
                return HTMLResponse("This link is from an earlier session. Open decomp.wtf again.", status_code=401)
            resp = RedirectResponse("/", status_code=303)
            resp.set_cookie(COOKIE, secret, httponly=True, samesite="strict", max_age=30 * 86400)
            return resp
        if not secrets.compare_digest(request.cookies.get(COOKIE, ""), secret):
            return HTMLResponse("<!doctype html><meta charset=utf-8><title>decomp.wtf</title>"
                                "<body style='font:16px system-ui;background:#0b0c0e;color:#e8e6e1;padding:3rem'>"
                                "Open decomp.wtf from its app icon or by running <code>decomp</code>.", status_code=401)
        return HTMLResponse(_static("index.html").decode(), headers={"Cache-Control": "no-store"})

    @mcp.custom_route("/assets/{name:path}", methods=["GET"])
    async def asset(request: Request) -> Response:
        if request.headers.get("host") not in allowed_hosts:
            return Response(status_code=403)
        name = request.path_params["name"]
        data = _static(name)
        if data is None:
            return Response(status_code=404)
        ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
        return Response(data, media_type=ctype, headers={"Cache-Control": "no-cache"})

    @mcp.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True, "app": "decomp-wtf", "version": __version__, "build": build_id})

    # ------------------------------------------------------------------ state

    def overviews() -> list[tuple[str, dict | None, str]]:
        """(slug, overview or None, why not) for every project. One that can't be read is still listed, with the
        reason: before, one odd project emptied the whole sidebar, or quietly went missing from it."""
        out = []
        for p in net.store.all("SELECT slug, name FROM projects ORDER BY id DESC"):
            try:
                out.append((p["slug"], net.overview(p["slug"]), ""))
            except Exception as e:  # noqa: BLE001
                jobs.logger.warning("project %s can't be read: %s", p["slug"], e, exc_info=not isinstance(e, NetworkError))
                out.append((p["slug"], {"slug": p["slug"], "title": p["name"] or p["slug"]}, job_error(e, jobs.log_path)))
        return out

    def state() -> dict:
        projects = [ov | ({"broken": why} if why else {}) for _, ov, why in overviews()]
        return {"version": __version__, "build": build_id, "install": {}, **hostenv.info(),
                "platform": sys.platform, "home": hostenv.shown_path(home.parent),
                "log_file": hostenv.shown_path(home / "logs" / "decomp.log"),
                "projects": projects, "agents": agents.detect(),
                "api_presets": agents.API_PRESETS, "settings": settings.public(), "mcp_url": mcp_url,
                "platform_status": PLATFORM_STATUS}

    def autopilot(slug: str) -> None:
        """Free matches first, in the background, when the user wants that (the default): a game started from
        scratch, on any platform, as soon as it's ready. A public decomp, or one not set up yet, says no."""
        if settings.data.get("autopilot", True):
            try:
                net.start_autopilot(slug)
            except NetworkError:
                pass

    def project_list() -> list[dict]:
        """The sidebar: every project with its progress and how many helper agents work on it right now."""
        running: dict[str, int] = {}
        for s in manager.sessions.values():
            if s.state in ("starting", "working", "waiting"):
                running[s.slug] = running.get(s.slug, 0) + 1
        out = []
        for slug, ov, why in overviews():
            out.append({k: ov.get(k) for k in ("slug", "title", "kind", "origin", "platform", "platform_name", "ready",
                                                "functions", "matched", "bytes", "matched_bytes", "last_activity")}
                       | {"working": running.get(slug, 0),
                          "autopilot": (ov.get("autopilot") or {}).get("state")} | ({"broken": why} if why else {}))
        return out

    @mcp.custom_route("/api/projects", methods=["GET"])
    async def api_projects(request: Request) -> Response:
        return guard(request) or JSONResponse(await call(project_list))

    @mcp.custom_route("/api/state", methods=["GET"])
    async def api_state(request: Request) -> Response:
        return guard(request) or JSONResponse(await call(state))

    @mcp.custom_route("/api/import", methods=["POST"])
    async def api_import(request: Request) -> Response:
        """A game the user owns: the demo, an upload streamed to disk (discs are gigabytes), or a local path."""
        if (bad := guard(request, write=True)):
            return bad
        q = request.query_params
        toolchain = q.get("toolchain") or None
        i64 = (q.get("i64") or "").strip().strip('"')
        if i64 and not Path(i64).expanduser().is_file():
            return fail(ValueError(f"no IDA database at {i64}"))
        if q.get("demo") == "1":
            game: bytes | Path | None = _static("demo/demo-quest-64.z64")
            if game is None:
                return fail(ValueError("the demo ROM is missing from this install"))
            name = "demo-quest-64.z64"
        else:
            if q.get("confirmed") != "1":
                return fail(ValueError("confirm that this is your own legally obtained copy of the game"))
            if q.get("path"):
                game = hostenv.local_path(q["path"])
                if not game.is_file():
                    return fail(ValueError(f"no file at {game}"))
                name = game.name
            else:
                name = Path(q.get("name") or "game.bin").name
                upload_dir = home / "uploads" / uuid.uuid4().hex[:8]  # keeps the file's own name
                upload_dir.mkdir(parents=True, exist_ok=True)
                game = upload_dir / name
                size = 0
                with open(game, "wb") as f:
                    async for chunk in request.stream():
                        size += len(chunk)
                        if size > MAX_DISC:
                            f.close()
                            game.unlink(missing_ok=True)
                            return fail(ValueError("that file is larger than any game disc"))
                        f.write(chunk)
                if size == 0:
                    game.unlink(missing_ok=True)
                    return fail(ValueError("the file was empty"))
        uploaded = isinstance(game, Path) and game.parent.parent == home / "uploads"

        def work(log):
            try:
                slug = net.import_rom(game, toolchain=toolchain, confirmed=True, name=name, log=log,
                                      ida_db=i64 or None)
            finally:
                if uploaded:
                    shutil.rmtree(game.parent, ignore_errors=True)
            settings.data["last_project"] = slug
            settings.save()
            # free matches first, in the background (native programs plan first: their autopilot starts from the plan)
            if not net.native_slug(slug):
                autopilot(slug)
            return {"slug": slug}
        return JSONResponse({"job": jobs.start("import", work)})

    MAP_KEYS = ("name", "vram", "size", "insns", "unit", "status", "best", "attempts", "agent", "matched_at", "matched_by")

    @mcp.custom_route("/api/map", methods=["GET"])
    async def api_map(request: Request) -> Response:
        """Every function, for the map and the table. `since`: the signature the GUI has; when nothing changed, the
        answer is just that (a big game's map is megabytes, and the GUI asks every few seconds). Rows go as arrays
        under `keys`, gzipped when the browser takes it."""
        if (bad := guard(request)):
            return bad
        slug = request.query_params.get("slug", "")

        def build() -> dict:
            sig = net.map_signature(slug)
            if request.query_params.get("since") == sig:
                return {"sig": sig, "same": True}
            rows = net.function_map(slug)
            return {"sig": sig, "keys": MAP_KEYS, "rows": [[r.get(k) for k in MAP_KEYS] for r in rows]}
        try:
            data = await call(build)
        except (NetworkError, ValueError) as e:
            return fail(e)
        raw = json.dumps(data, separators=(",", ":")).encode()
        if len(raw) > 4096 and "gzip" in request.headers.get("accept-encoding", ""):
            import gzip
            return Response(gzip.compress(raw, 1), media_type="application/json",
                            headers={"Content-Encoding": "gzip", "Vary": "Accept-Encoding"})
        return Response(raw, media_type="application/json")

    @mcp.custom_route("/api/log", methods=["GET"])
    async def api_log(request: Request) -> Response:
        """The end of decomp.wtf's log, to read or attach to a bug report (the app's data folder isn't always at
        hand: in Docker it's inside the container)."""
        if (bad := guard(request)):
            return bad
        path = home / "logs" / "decomp.log"
        try:
            with open(path, "rb") as f:
                f.seek(max(0, path.stat().st_size - (512 << 10)))
                text = f.read().decode("utf-8", "replace")
        except OSError:
            text = "(nothing logged yet)"
        return Response(text, media_type="text/plain; charset=utf-8",
                        headers={"Content-Disposition": 'inline; filename="decomp.log"'})

    @mcp.custom_route("/api/job", methods=["GET"])
    async def api_job(request: Request) -> Response:
        if (bad := guard(request)):
            return bad
        job = jobs.jobs.get(request.query_params.get("id", ""))
        return JSONResponse(job) if job else fail(ValueError("no such job"), 404)

    def worker_agent(request: Request):
        auth = request.headers.get("authorization", "")
        token = auth.split(None, 1)[1] if auth.lower().startswith("bearer ") else ""
        return net.authenticate(token)

    @mcp.custom_route("/api/worker/claim", methods=["POST"])
    async def api_worker_claim(request: Request) -> Response:
        """A remote donated-compute worker claims one job with its agent token."""
        if request.headers.get("host") not in allowed_hosts:
            return JSONResponse({"error": "bad host"}, status_code=403)
        try:
            agent = worker_agent(request)
        except NetworkError as e:
            return fail(e, 401)
        data = await body(request)
        try:
            job = await call(core_worker.claim, net, agent, data.get("project") or None,
                             data.get("function") or None)
        except NetworkError as e:
            return fail(e, 409)
        return JSONResponse({"job": job})

    @mcp.custom_route("/api/worker/submit", methods=["POST"])
    async def api_worker_submit(request: Request) -> Response:
        if request.headers.get("host") not in allowed_hosts:
            return JSONResponse({"error": "bad host"}, status_code=403)
        try:
            agent = worker_agent(request)
        except NetworkError as e:
            return fail(e, 401)
        data = await body(request)
        project, function, source = (str(data.get(k) or "") for k in ("project", "function", "source"))
        if not project or not function or not source:
            return fail(ValueError("project, function and source are required"))
        try:
            result = await call(core_worker.submit, net, agent, project, function, source)
        except NetworkError as e:
            return fail(e, 409)
        return JSONResponse(result)

    @mcp.custom_route("/api/worker/release", methods=["POST"])
    async def api_worker_release(request: Request) -> Response:
        if request.headers.get("host") not in allowed_hosts:
            return JSONResponse({"error": "bad host"}, status_code=403)
        try:
            agent = worker_agent(request)
        except NetworkError as e:
            return fail(e, 401)
        data = await body(request)
        try:
            await call(core_worker.release_claim, net, agent,
                       str(data.get("function") or ""), data.get("project") or None)
        except NetworkError as e:
            return fail(e, 409)
        return JSONResponse({"ok": True})

    # ------------------------------------------------------------------ projects

    def with_project(fn):
        async def handler(request: Request) -> Response:
            if (bad := guard(request, write=request.method == "POST")):
                return bad
            data = await body(request) if request.method == "POST" else {}
            slug = data.get("slug") or request.query_params.get("slug", "")
            try:
                return JSONResponse(await call(lambda: fn(slug, request, data)))
            except (NetworkError, NativeError, ValueError, OSError) as e:
                return fail(e)
        return handler

    def p_overview(slug, request, data):
        settings.data["last_project"] = slug
        settings.save()
        return net.overview(slug)

    def p_live(slug, request, data):
        q = request.query_params
        out = net.live(slug, int(q.get("e", 0) or 0), int(q.get("a", 0) or 0))
        try:
            since = json.loads(q.get("s") or "{}")
        except ValueError:
            since = {}
        out["sessions"] = [s for s in manager.snapshot(since) if s["slug"] == slug]
        out["reports"] = net.reports(slug)
        return out

    def p_reports(slug, request, data):
        return {"reports": net.reports(slug)}

    def p_compiler(slug, request, data):
        net.set_compiler(slug, str(data.get("toolchain", "")), data.get("flags") or None)
        return net.overview(slug)

    def p_export(slug, request, data):
        def work(log):
            res = net.export_rom(slug, log=log)
            return {k: v for k, v in res.items() if k != "log"} | {"log": res.get("log", "")[-1500:]}
        return {"job": jobs.start("export", work)}

    def p_open(slug, request, data):
        why = hostenv.open_folder(Path(net.project_row(slug)["root"]))
        return {"ok": why is None, "message": why}

    def p_delete(slug, request, data):
        manager.stop()
        proj = net.project_row(slug)
        net.remove_project(slug)
        if data.get("files"):
            shutil.rmtree(proj["root"], ignore_errors=True)
        if settings.data.get("last_project") == slug:
            settings.data["last_project"] = None
            settings.save()
        return {"ok": True}

    def p_manual(slug, request, data):
        name = f"manual-{secrets.token_hex(2)}"
        agent, token = net.local_agent(name)
        manager.assignments[agent.id] = slug
        return {"agent": name, "url": mcp_url, "token": token,
                "claude": f'claude mcp add --transport http decomp {mcp_url} --header "Authorization: Bearer {token}"',
                "json": json.dumps({"mcpServers": {"decomp": {"type": "http", "url": mcp_url,
                                                              "headers": {"Authorization": f"Bearer {token}"}}}}, indent=2)}

    def p_try(slug, request, data):
        """You, editing a function in the GUI: judged like an agent's attempt (and credited to "you")."""
        agent, _ = net.local_agent("you")
        res = net.attempt(agent, str(data.get("name", "")), str(data.get("source", "")), slug)
        return {"score": res["score"], "matched": res["matched"], "text": res["text"][-4000:]}

    def p_release(slug, request, data):
        agent, _ = net.local_agent("you")
        try:
            net.release(agent, str(data.get("name", "")), "", slug)
        except NetworkError:
            pass  # not yours (any more): nothing to give back
        return {"ok": True}

    def p_instructions(slug, request, data):
        net.set_instructions(slug, str(data.get("text", "")))
        return net.overview(slug)

    def p_priority(slug, request, data):
        return {"priority": net.set_priority(slug, str(data.get("name", "")), bool(data.get("on", True)))}

    def p_note(slug, request, data):
        """A note from you on a function (or the whole project): agents read notes when they claim it."""
        agent, _ = net.local_agent("you")
        text = str(data.get("text", "")).strip()
        if not text:
            raise ValueError("write the note first")
        return {"message": net.add_note(agent, slug, text[:2000], str(data.get("function", "")) or None)}

    def p_signature(slug, request, data):
        """You, editing one function's declaration from the Header tab."""
        agent, _ = net.local_agent("you")
        native = net.native_slug(slug)
        if not native:
            return {"message": "signatures are for native programs (ELF/PE)"}
        return {"message": net.native.set_signature(
            agent, native, str(data.get("name", "")), str(data.get("ret", "")),
            params=str(data.get("params", "")), const=str(data.get("const", "")),
            static=str(data.get("static", "")), virtual=str(data.get("virtual", "")),
            note=str(data.get("note", "")))}

    def p_mode(slug, request, data):
        """You, choosing whether a function is a body target, header-only, or skipped."""
        agent, _ = net.local_agent("you")
        return {"message": net.set_mode(agent, str(data.get("name", "")), str(data.get("mode", "")),
                                        str(data.get("note", "")), slug)}

    def p_autopilot(slug, request, data):
        if data.get("action") == "stop":
            net.stop_autopilot(slug)
        else:
            net.start_autopilot(slug)
        return net.overview(slug)

    routes = {
        "/api/project": (p_overview, ["GET"]),
        "/api/live": (p_live, ["GET"]),
        "/api/reports": (p_reports, ["GET"]),
        "/api/function": (lambda s, r, d: net.function_detail(s, r.query_params.get("name", "")), ["GET"]),
        "/api/header": (lambda s, r, d: {"header": net.generated_header(s, r.query_params.get("name", ""))}, ["GET"]),
        "/api/diff": (lambda s, r, d: net.function_diff(s, r.query_params.get("name", ""),
                                                        r.query_params.get("which", "latest")), ["GET"]),
        "/api/compiler": (p_compiler, ["POST"]), "/api/export": (p_export, ["POST"]), "/api/open": (p_open, ["POST"]),
        "/api/delete": (p_delete, ["POST"]), "/api/agents/manual": (p_manual, ["POST"]),
        "/api/try": (p_try, ["POST"]), "/api/release": (p_release, ["POST"]),
        "/api/autopilot": (p_autopilot, ["POST"]), "/api/instructions": (p_instructions, ["POST"]),
        "/api/priority": (p_priority, ["POST"]), "/api/note": (p_note, ["POST"]),
        "/api/mode": (p_mode, ["POST"]), "/api/signature": (p_signature, ["POST"]),
        "/api/stats": (lambda s, r, d: net.stats(s), ["GET"]),
    }
    for path, (fn, methods) in routes.items():
        mcp.custom_route(path, methods=methods)(with_project(fn))

    # ------------------------------------------------------------------ native programs (ELF/PE)

    def native_of(slug: str):
        if not net.native_slug(slug):
            raise NetworkError(f"{slug} isn't a native program project")
        return net.project_row(slug)

    @mcp.custom_route("/api/native/plan", methods=["GET"])
    async def api_native_plan(request: Request) -> Response:
        if (bad := guard(request)):
            return bad
        slug = request.query_params.get("slug") or settings.data.get("last_project") or ""
        try:
            native_of(slug)
            return JSONResponse(await call(net.native.plan_view, slug))
        except (NetworkError, ValueError, OSError) as e:
            return fail(e)

    @mcp.custom_route("/api/native/environments", methods=["GET"])
    async def api_native_environments(request: Request) -> Response:
        """Read-only per-compile-unit environment report (resolver preview)."""
        if (bad := guard(request)):
            return bad
        slug = str(request.query_params.get("slug") or settings.data.get("last_project") or "")
        try:
            native_of(slug)
            limit = int(request.query_params.get("limit") or 80)
            return JSONResponse(await call(lambda: net.native.environment_view(slug, limit=limit)))
        except (NetworkError, ValueError, OSError) as e:
            return fail(e)

    @mcp.custom_route("/api/native/analyze", methods=["POST"])
    async def api_native_analyze(request: Request) -> Response:
        if (bad := guard(request, write=True)):
            return bad
        data = await body(request)
        slug = str(data.get("slug") or settings.data.get("last_project") or "")
        try:
            native_of(slug)
        except (NetworkError, ValueError) as e:
            return fail(e)

        def work(log):
            from ..core import analyze as analyze_mod
            analyze_mod.analyze(net, slug, force=bool(data.get("force")), log=log)
            return {"slug": slug}
        return JSONResponse({"job": jobs.start("native-analysis", work)})

    @mcp.custom_route("/api/native/unit", methods=["GET"])
    async def api_native_unit(request: Request) -> Response:
        """One unit's functions with their treatments: the plan tree's leaves."""
        if (bad := guard(request)):
            return bad
        slug = str(request.query_params.get("slug") or settings.data.get("last_project") or "")
        path = str(request.query_params.get("path") or "")
        try:
            native_of(slug)
        except (NetworkError, ValueError) as e:
            return fail(e)
        try:
            return JSONResponse(await call(lambda: net.native.unit_functions(slug, path)))
        except (NetworkError, ValueError, OSError) as e:
            return fail(e)

    @mcp.custom_route("/api/native/find", methods=["GET"])
    async def api_native_find(request: Request) -> Response:
        """Functions across the whole analysis by name fragment or address — the plan's function search."""
        if (bad := guard(request)):
            return bad
        slug = str(request.query_params.get("slug") or settings.data.get("last_project") or "")
        q = str(request.query_params.get("q") or "")
        try:
            limit = int(request.query_params.get("limit") or 200)
        except ValueError:
            limit = 200
        try:
            native_of(slug)
        except (NetworkError, ValueError) as e:
            return fail(e)
        try:
            return JSONResponse(await call(lambda: net.native.find_functions(slug, q, limit)))
        except (NetworkError, ValueError, OSError) as e:
            return fail(e)

    @mcp.custom_route("/api/native/glue", methods=["POST"])
    async def api_native_glue(request: Request) -> Response:
        """One switch for the import machinery (PLT / CRT / extern slots) wherever it sits."""
        if (bad := guard(request, write=True)):
            return bad
        data = await body(request)
        slug = str(data.get("slug") or "")
        treatment = str(data.get("treatment") or "")

        def go():
            from ..core import plan as plan_mod
            native_of(slug)
            res = plan_mod.set_glue(net, slug, treatment)
            return {"applied": True, "glue": res["glue"], "functions": res["functions"],
                    "plan": net.native.plan_view(slug)}
        try:
            return JSONResponse(await call(go))
        except (NetworkError, ValueError, OSError) as e:
            return fail(e)

    @mcp.custom_route("/api/native/treatment", methods=["POST"])
    async def api_native_treatment(request: Request) -> Response:
        """Set one file's treatment, or one function's with `ea`. Excluding a file whose callers
        would break returns the cascade preview first (applied=False); the UI confirms and posts
        again with confirm=1. A single function has no cascade: callers still get its declaration."""
        if (bad := guard(request, write=True)):
            return bad
        data = await body(request)
        slug = str(data.get("slug") or "")
        path = str(data.get("path") or "")
        treatment = str(data.get("treatment") or "")
        ea = data.get("ea")

        def go():
            from ..core import plan as plan_mod
            native_of(slug)
            if ea is not None:
                plan_mod.set_function(net, slug, path, int(ea), treatment)
                return {"applied": True, "forced": [], "plan": net.native.plan_view(slug)}
            if treatment == "exclude" and not data.get("confirm"):
                analysis = net.native.analysis(net.project_row(slug))
                if analysis is not None:
                    plan = plan_mod.load(net, slug)
                    forced = plan_mod.cascade(analysis["graph"], plan_mod.effective(analysis, plan), path)
                    if forced:
                        return {"applied": False, "forced": forced}
            res = plan_mod.set_treatment(net, slug, path, treatment)
            return {"applied": True, "forced": res["forced"], "plan": net.native.plan_view(slug)}
        try:
            return JSONResponse(await call(go))
        except (NetworkError, ValueError, OSError) as e:
            return fail(e)

    @mcp.custom_route("/api/native/treatments", methods=["POST"])
    async def api_native_treatments(request: Request) -> Response:
        """Bulk treatment: one treatment for many files (a directory, a selection). Excluding
        previews the cascade (applied=False) unless confirm=1."""
        if (bad := guard(request, write=True)):
            return bad
        data = await body(request)
        slug = str(data.get("slug") or "")
        paths = [str(p) for p in (data.get("paths") or [])]
        treatment = str(data.get("treatment") or "")

        def go():
            from ..core import plan as plan_mod
            native_of(slug)
            if not paths:
                return {"applied": False, "forced": []}
            if treatment == "exclude" and not data.get("confirm"):
                analysis = net.native.analysis(net.project_row(slug))
                if analysis is not None:
                    plan = plan_mod.load(net, slug)
                    forced = plan_mod.preview_many(analysis["graph"], plan_mod.effective(analysis, plan), paths, treatment)
                    forced = [f for f in forced if f not in paths]
                    if forced:
                        return {"applied": False, "forced": forced}
            res = plan_mod.set_many(net, slug, paths, treatment)
            return {"applied": True, "forced": res["forced"], "plan": net.native.plan_view(slug)}
        try:
            return JSONResponse(await call(go))
        except (NetworkError, ValueError, OSError) as e:
            return fail(e)

    @mcp.custom_route("/api/native/confirm", methods=["POST"])
    async def api_native_confirm(request: Request) -> Response:
        if (bad := guard(request, write=True)):
            return bad
        data = await body(request)
        slug = str(data.get("slug") or "")
        try:
            native_of(slug)
        except (NetworkError, ValueError) as e:
            return fail(e)

        def work(log):
            from ..core import plan as plan_mod
            counts = plan_mod.confirm(net, slug, log=log)
            return {"slug": slug, "counts": counts}
        return JSONResponse({"job": jobs.start("native-plan", work)})

    @mcp.custom_route("/api/native/compiler", methods=["POST"])
    async def api_native_compiler(request: Request) -> Response:
        """The user's driver, flags and container image for this project (empty command = auto-detect,
        empty image = compile on this machine)."""
        if (bad := guard(request, write=True)):
            return bad
        data = await body(request)
        slug = str(data.get("slug") or "")
        try:
            native_of(slug)
            command = str(data.get("command") or "").strip()
            image = str(data.get("image") or "").strip()
            platform = str(data.get("platform") or "").strip()
            flags = data.get("flags")
            flags = shlex.split(flags) if isinstance(flags, str) else [str(f) for f in (flags or [])]

            def change(cfg):
                c = cfg.setdefault("compiler", {})
                c["command"], c["flags"] = command, flags
                if image:
                    c["image"] = image
                else:
                    c.pop("image", None)
                if platform:
                    c["platform"] = platform
                else:
                    c.pop("platform", None)
            net._update_cfg(slug, change)
            return JSONResponse(net.native.compiler_view(slug))
        except (NetworkError, ValueError, OSError) as e:
            return fail(e)

    @mcp.custom_route("/api/native/pull", methods=["POST"])
    async def api_native_pull(request: Request) -> Response:
        """Fetch the project's container image — only ever started by this explicit click, never on
        its own: switching compiles into docker (and a multi-GB download) is the user's call."""
        if (bad := guard(request, write=True)):
            return bad
        data = await body(request)
        slug = str(data.get("slug") or "")
        try:
            native_of(slug)
        except (NetworkError, ValueError) as e:
            return fail(e)
        return JSONResponse({"job": jobs.start("native-image", lambda log: net.native.pull_image(slug, log=log))})

    # ------------------------------------------------------------------ installs, agents, settings

    @mcp.custom_route("/api/agents/install", methods=["POST"])
    async def api_agent_install(request: Request) -> Response:
        if (bad := guard(request, write=True)):
            return bad
        kind = agents.KINDS.get(agents.kind_id(str((await body(request)).get("kind", ""))))
        if kind is None or not kind.install:
            return fail(ValueError("nothing to install"))
        cmd = kind.install["windows" if sys.platform == "win32" else "unix"]
        env = None
        if sys.platform == "win32":
            env = dict(os.environ, PATH=agents.search_path())  # Node.js installed since the app started counts
            if cmd.startswith("npm ") and not shutil.which("npm", path=env["PATH"]):
                return fail(ValueError(f"{kind.name} is installed with npm: install Node.js from https://nodejs.org "
                                       "first (the LTS version), then try again"))

        def work(log):
            log(f"$ {cmd}")
            if sys.platform == "win32":
                # Node.js's npm is a PowerShell script (npm.ps1) that Windows' default execution policy won't run;
                # output as UTF-8 so it reads right here; never wait at a prompt nobody sees
                argv = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                        f"[Console]::OutputEncoding = [Text.Encoding]::UTF8; {cmd}"]
            else:
                argv = ["bash", "-lc", cmd]
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                    errors="replace", env=env)
            for line in proc.stdout:
                log(line.rstrip())
            if proc.wait() != 0:
                raise RuntimeError(f"the installer exited with code {proc.returncode}")
            agents._versions.pop(kind.id, None)
            return {"kind": kind.id}
        return JSONResponse({"job": jobs.start("agent-install", work)})

    @mcp.custom_route("/api/agents/start", methods=["POST"])
    async def api_agents_start(request: Request) -> Response:
        if (bad := guard(request, write=True)):
            return bad
        data = await body(request)
        kind, slug = str(data.get("kind", "")), str(data.get("slug", ""))
        given = data.get("options") or {}
        options = {k: v for k, v in given.items() if k in ("model", "per_session")}
        options.setdefault("per_session", settings.data.get("per_session", agents.PER_SESSION))
        count = max(1, min(int(data.get("count", 1)), 8))
        picked: list[str] = []
        try:
            net.project_row(slug)
            if kind == "api":
                picked = [str(e) for e in (given.get("endpoints") or ([given["endpoint"]] if given.get("endpoint") else []))]
                plan = _spread(settings, manager, picked, count, given)
                ids = [sid for entry, n in plan for sid in manager.start(kind, slug, n, options | _session_options(entry))]
            else:
                ids = manager.start(kind, slug, count, options)
        except (NetworkError, ValueError) as e:
            return fail(e)
        # remembered, so the next start is one click; models typed in come back as suggestions
        model = str(options.get("model") or "")
        settings.data["launcher"] = {"kind": kind, "model": model, "count": count} | ({"endpoints": picked} if picked else {})
        if model and kind != "api":
            recent = settings.data.setdefault("recent_models", {}).setdefault(kind, [])
            settings.data["recent_models"][kind] = [model] + [m for m in recent if m != model][:7]
        settings.save()
        return JSONResponse({"started": ids})

    @mcp.custom_route("/api/connect", methods=["GET", "POST"])
    async def api_connect(request: Request) -> Response:
        """Your agents (Claude Code, Codex, ...) with decomp.wtf's tools: whether they have them, and adding them."""
        if (bad := guard(request, write=request.method == "POST")):
            return bad
        if request.method == "POST":
            kind = str((await body(request)).get("id", ""))
            try:
                msg = await anyio.to_thread.run_sync(lambda: connect.connect(kind))
            except (ValueError, OSError, subprocess.TimeoutExpired) as e:
                return fail(e)
            return JSONResponse({"ok": True, "message": msg})

        def rows():
            from concurrent.futures import ThreadPoolExecutor

            found = [a for a in agents.detect() if a["id"] in connect.LABEL]
            with ThreadPoolExecutor(len(found) or 1) as pool:  # each agent's own CLI answers; ask them all at once
                linked = list(pool.map(lambda a: a["installed"] and connect.status(a["id"]), found))
            return [{"id": a["id"], "name": a["name"], "installed": a["installed"], "connected": ok,
                     "command": connect.shown(a["id"])} for a, ok in zip(found, linked)]
        if (host := hostenv.host_bridge()) is not None:  # the user's agents live outside decomp.wtf's Linux
            return JSONResponse({"agents": [], "bridge": host, "host_bridge": host, **hostenv.info()})
        return JSONResponse({"agents": await anyio.to_thread.run_sync(rows), "bridge": connect.bridge_command()})

    @mcp.custom_route("/api/agents/token", methods=["POST"])
    async def api_agents_token(request: Request) -> Response:
        """An identity for an agent the user talks to, connecting through `decomp mcp`."""
        if (bad := guard(request, write=True)):
            return bad
        data = await body(request)
        try:
            agent, token = net.chat_agent(str(data.get("name") or "chat"))
        except NetworkError as e:
            return fail(e)
        return JSONResponse({"agent": agent.name, "token": token, "url": mcp_url})

    @mcp.custom_route("/api/agents/stop", methods=["POST"])
    async def api_agents_stop(request: Request) -> Response:
        if (bad := guard(request, write=True)):
            return bad
        data = await body(request)
        if agent := str(data.get("agent") or ""):
            # the "connected agent" card's Release: a claim whose session is gone (the app was
            # killed mid-run, or the run crashed) would otherwise block the function until its TTL
            freed = net.release_claims(agent, str(data.get("slug") or "") or None)
            return JSONResponse({"ok": True, "released": freed})
        if data.get("remove"):
            manager.remove(str(data.get("id")))
        elif data.get("slug"):  # every helper on one project
            for s in list(manager.sessions.values()):
                if s.slug == data["slug"] and s.state in ("starting", "working", "waiting"):
                    manager.stop(s.id)
        else:
            manager.stop(data.get("id") or None)
        return JSONResponse({"ok": True})

    @mcp.custom_route("/api/settings", methods=["POST"])
    async def api_settings(request: Request) -> Response:
        if (bad := guard(request, write=True)):
            return bad
        data = await body(request)
        if isinstance(data.get("api"), dict):  # (before 0.10.1: the one endpoint there was) the first one
            first = settings.endpoints()[0]["id"] if settings.endpoints() else ""
            settings.save_endpoint(data["api"] | {"id": first})
        if isinstance(data.get("endpoint"), dict):
            settings.save_endpoint(data["endpoint"])
        if data.get("remove_endpoint"):
            settings.remove_endpoint(str(data["remove_endpoint"]))
            for sid, sess in list(manager.sessions.items()):  # its sessions stop with it
                if sess.kind == "api" and sess.options.get("endpoint") == str(data["remove_endpoint"]):
                    manager.stop(sid)
        if "per_session" in data:
            settings.data["per_session"] = max(1, min(int(data["per_session"]), 20))
        if "autopilot" in data:
            settings.data["autopilot"] = bool(data["autopilot"])
        if "budget_usd" in data:
            settings.data["budget_usd"] = max(0.0, float(data["budget_usd"] or 0))
        if "auto_update" in data:
            settings.data["auto_update"] = bool(data["auto_update"])
        if "check_updates" in data:
            settings.data["check_updates"] = bool(data["check_updates"])
        settings.save()
        return JSONResponse(settings.public())

    @mcp.custom_route("/api/quit", methods=["POST"])
    async def api_quit(request: Request) -> Response:
        if (bad := guard(request, write=True)):
            return bad

        def bye():
            manager.stop()
            manager.on_stop()
            time.sleep(0.5)
            os._exit(0)
        threading.Thread(target=bye, daemon=True).start()
        return JSONResponse({"ok": True})

    security = TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=sorted(allowed_hosts),
                                         allowed_origins=[f"http://{h}" for h in sorted(allowed_hosts)])
    return mcp, manager, security
