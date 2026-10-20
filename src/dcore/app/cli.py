"""`decomp`: start decomp.wtf (or bring the running one to the front) and open it in the browser."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from ..core import hostenv

DEFAULT_PORT = int(os.environ.get("DECOMP_PORT") or 6464)


def home_dir() -> Path:
    return Path(os.environ.get("DECOMP_HOME", Path.home() / "Decomp")).expanduser()


def _alive(port: int) -> bool:
    return _running_version(port) is not None


def _running_version(port: int) -> str | None:
    """The version of the decomp.wtf answering on this port ("" when it doesn't say), or None."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1.5) as r:
            data = json.loads(r.read())
            return str(data.get("version") or "") if data.get("app") == "decomp-wtf" else None
    except (OSError, ValueError):
        return None


def _version_key(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3]) or (0,)


def replace_older(state_file: Path, log=print) -> dict | None:
    """The running app's {port, secret} when it's this version or newer. An older one (still running after an
    upgrade) is stopped, so the new version starts in its place: returns None then, and when nothing runs. A newer
    app is never stopped by an older `decomp mcp` (an agent may still be set up with an older install's path)."""
    try:
        prev = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    running = _running_version(prev.get("port") or 0)
    if running is None:
        return None
    mine = __import__("dcore").__version__
    if running == mine or _version_key(running) > _version_key(mine):
        return prev
    log(f"decomp.wtf {running} is still running; restarting it as {mine}")
    req = urllib.request.Request(f"http://127.0.0.1:{prev['port']}/api/quit", method="POST", data=b"{}",
                                 headers={"Cookie": f"decomp_live={prev['secret']}", "X-Decomp": "1",
                                          "Host": f"127.0.0.1:{prev['port']}", "Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10)
    except OSError:
        pass
    for _ in range(100):
        if _running_version(prev["port"]) is None:
            break
        time.sleep(0.1)
    return None


def _bind_address() -> str:
    """127.0.0.1, except in decomp.wtf's Docker container: there the published port (127.0.0.1 on the computer
    itself) arrives from outside the container. Host headers are still checked on every request (server.py)."""
    return os.environ.get("DECOMP_BIND") or ("0.0.0.0" if hostenv.runtime() == "docker" else "127.0.0.1")


def _listen(start: int, exact: bool = False) -> socket.socket:
    """A listening socket on the first free port from `start`, kept open and handed to the server: two decomp.wtf
    instances starting at the same moment can't both pick the same port. `exact`: that port or nothing (a restart
    into an update keeps its port, so the open browser tab carries on; Docker publishes one port)."""
    for port in range(start, start + (1 if exact else 50)):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if sys.platform != "win32":  # the previous run's connections may linger in TIME_WAIT for a minute
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        for attempt in range(50 if exact else 1):
            try:
                sock.bind((_bind_address(), port))
                sock.listen(128)
                return sock
            except OSError:
                time.sleep(0.2 if exact else 0)
        sock.close()
    raise SystemExit(f"port {start} is taken" if exact else "no free port for decomp.wtf")


def _open_when_ready(url: str, port: int) -> None:
    def wait():
        for _ in range(100):
            if _alive(port):
                hostenv.open_url(url)
                return
            time.sleep(0.2)
    threading.Thread(target=wait, daemon=True).start()


def _restart_state() -> dict | None:
    """When the app is restarted it keeps the running one's port and secret (via DECOMP_RESTART)."""
    raw = os.environ.pop("DECOMP_RESTART", "")
    try:
        data = json.loads(raw) if raw else None
        return data if isinstance(data, dict) and data.get("port") and data.get("secret") else None
    except ValueError:
        return None


def run(args) -> int:
    import uvicorn

    from ..core.engine import Engine
    from .server import build

    home = home_dir()
    internal = home / ".decomp"
    internal.mkdir(parents=True, exist_ok=True)
    if sys.stdout is None:  # started without a console (pythonw: Windows' startup apps): what it says goes to app.log
        sys.stdout = sys.stderr = open(internal / "app.log", "a", encoding="utf-8", buffering=1)
    state_file = internal / "server.json"
    restarted = _restart_state()
    prev = None if restarted else replace_older(state_file)
    if prev:
        url = f"http://127.0.0.1:{prev['port']}/?k={prev['secret']}"
        print(f"decomp.wtf is already running: {url}")
        if not args.no_browser and not hostenv.open_url(url):
            print("open that address in your browser")
        return 0

    sock = _listen(restarted["port"] if restarted else args.port, exact=bool(restarted) or _fixed_port())
    port = sock.getsockname()[1]
    secret = restarted["secret"] if restarted else secrets.token_urlsafe(24)
    state_file.write_text(json.dumps({"port": port, "secret": secret, "pid": os.getpid()}), encoding="utf-8")
    try:
        os.chmod(state_file, 0o600)
    except OSError:
        pass
    net = Engine(internal / "decomp.db", home)

    def _check_units() -> None:
        # Entry order is part of the header's meaning: a render-order change can leave an existing
        # unit wedged (single-entry repairs are correctly refused). Flag it as a report at startup
        # instead of letting an agent discover it mid-session.
        try:
            for row in net.store.all("SELECT slug FROM projects"):
                net.validate_units(row["slug"])
        except Exception as e:
            print(f"unit check skipped: {e}", flush=True)

    threading.Thread(target=_check_units, name="unit-health", daemon=True).start()
    mcp, manager, security = build(net, internal, port, secret)
    app = mcp.streamable_http_app(transport_security=security, max_request_body_size=80 * 1024 * 1024, host="127.0.0.1")
    url = f"http://127.0.0.1:{port}/?k={secret}"
    print(f"decomp.wtf {__import__('dcore').__version__} on {url}\nyour projects: {hostenv.shown_path(home)}"
          + ("\nupdated and restarted" if restarted else "\nstop with Ctrl-C"), flush=True)
    if not args.no_browser and not restarted:
        _open_when_ready(url, port)
    try:
        uvicorn.Server(uvicorn.Config(app, log_level="warning")).run(sockets=[sock])
    finally:
        manager.stop()
        manager.on_stop()
    return 0


def _fixed_port() -> bool:
    """Docker publishes exactly one port: decomp.wtf must listen on it, not on the next free one."""
    return hostenv.runtime() == "docker" and bool(os.environ.get("DECOMP_PORT"))


def url_cmd(args) -> int:
    """Print the address that opens the app (starting it in the background first if needed)."""
    from .bridge import ensure_app

    info = ensure_app(home_dir())
    print(f"http://127.0.0.1:{info['port']}/?k={info['secret']}")
    return 0


def stop(args) -> int:
    state_file = home_dir() / ".decomp" / "server.json"
    try:
        prev = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        print("decomp.wtf is not running")
        return 0
    if not _alive(prev.get("port", 0)):
        print("decomp.wtf is not running")
        return 0
    req = urllib.request.Request(f"http://127.0.0.1:{prev['port']}/api/quit", method="POST", data=b"{}",
                                 headers={"Cookie": f"decomp_live={prev['secret']}", "X-Decomp": "1",
                                          "Host": f"127.0.0.1:{prev['port']}", "Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5)
    except OSError:
        pass
    print("decomp.wtf stopped")
    return 0


def connect_agents(args) -> int:
    """Give the AI agents you use decomp.wtf's tools: then ask them to decompile your game."""
    from . import agents, connect

    if "gemini" in args.agents:
        print("Gemini CLI was retired by Google; its successor is Antigravity CLI (agy): connecting that instead.")
    args.agents = [agents.kind_id(a) for a in args.agents]
    unknown = [a for a in args.agents if a not in connect.LABEL]
    if unknown:
        print(f"unknown agent {unknown[0]!r}: use claude, codex, antigravity or opencode")
        return 2
    found = [a for a in agents.detect() if a["id"] in connect.LABEL and a["installed"]]
    wanted = [a for a in found if not args.agents or a["id"] in args.agents]
    if not found:
        print("No agent CLI found (Claude Code, Codex, Antigravity CLI or opencode). Install one, then run `decomp connect`.")
        return 1
    for a in wanted:
        if args.list:
            print(f"{a['name']}: {'connected' if connect.status(a['id']) else 'not connected'}")
            continue
        try:
            connect.connect(a["id"])
            print(f"{a['name']}: connected")
        except (ValueError, OSError) as e:
            print(f"{a['name']}: {e}")
    if not args.list:
        print('Now ask your agent, for example: "decompile my game at ~/roms/game.z64"')
    return 0


def _api(path: str, body: dict | None = None) -> dict:
    """Call the running app's API (for commands that act on it, like `decomp share`)."""
    state = home_dir() / ".decomp" / "server.json"
    try:
        info = json.loads(state.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise SystemExit("decomp.wtf isn't running: start it with `decomp --no-browser`") from None
    if not _alive(info.get("port", 0)):
        raise SystemExit("decomp.wtf isn't running: start it with `decomp --no-browser`")
    req = urllib.request.Request(f"http://127.0.0.1:{info['port']}{path}", method="POST" if body is not None else "GET",
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Cookie": f"decomp_live={info['secret']}", "X-Decomp": "1",
                                          "Host": f"127.0.0.1:{info['port']}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise SystemExit(json.loads(e.read() or b"{}").get("error") or str(e)) from None


def _wait(job: str, what: str) -> dict:
    last = ""
    for _ in range(7200):
        st = _api(f"/api/job?id={job}")
        if st["log"] and st["log"][-1] != last:
            last = st["log"][-1]
            print(f"  {last}")
        if st["state"] != "running":
            break
        time.sleep(0.5)
    if st["state"] != "done":
        raise SystemExit(st.get("error") or f"{what} failed")
    return st["result"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="decomp", description="decomp.wtf: your AI agents decompile your games, matching byte for byte")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--no-browser", action="store_true", help="don't open the browser")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("stop", help="stop the running app")
    sub.add_parser("url", help="print the address that opens the app (starts it if needed)")
    c = sub.add_parser("connect", help="give your AI agents (Claude Code, Codex, Antigravity CLI, opencode) decomp.wtf's tools")
    c.add_argument("agents", nargs="*", metavar="agent", help="claude, codex, antigravity (agy) or opencode (default: every one installed)")
    c.add_argument("--list", action="store_true", help="only show which are connected")
    m = sub.add_parser("mcp", help="serve decomp.wtf to the AI agent you talk to (stdio MCP; starts the app if needed)")
    m.add_argument("--name", default=os.environ.get("DECOMP_AGENT_NAME") or "chat",
                   help="how this agent shows up in the app (e.g. claude-code; or set DECOMP_AGENT_NAME)")
    w = sub.add_parser("worker", help="donate local compute: claim jobs and run an external solver")
    w.add_argument("--project", help="only take jobs from this project slug")
    w.add_argument("--function", help="only take this exact function name (useful for a live test)")
    w.add_argument("--agent", default=os.environ.get("DECOMP_WORKER_NAME") or "worker",
                   help="worker identity in the app")
    w.add_argument("--solver", required=True,
                   help="command that reads job JSON on stdin and prints replacement source")
    w.add_argument("--count", type=int, default=1, help="attempts to run (0 = until no jobs remain)")
    w.add_argument("--timeout", type=float, default=300.0, help="seconds per solver invocation")
    w.add_argument("--url", help="coordinator URL for remote donated compute")
    w.add_argument("--token", help="agent token (dn_...) for --url")
    args = ap.parse_args(argv)
    __import__("dcore").utf8_output()
    if args.cmd == "mcp":
        from .bridge import main as bridge
        return bridge(args.name)
    return {"stop": stop, "connect": connect_agents, "url": url_cmd,
            "worker": worker_cmd}.get(args.cmd, run)(args)


def worker_cmd(args) -> int:
    from ..core import worker
    from ..core.engine import Engine

    if args.url:
        if not args.token:
            raise SystemExit("--url needs --token (dn_...) from the coordinator")
        stats = worker.run_remote(args.url, args.token, command=args.solver, project=args.project,
                                  function=args.function, count=args.count, timeout=args.timeout)
    else:
        home = home_dir()
        net = Engine(home / ".decomp" / "decomp.db", home)
        agent, _ = net.local_agent(args.agent)
        stats = worker.run_worker(net, agent, command=args.solver, project=args.project,
                                  function=args.function, count=args.count, timeout=args.timeout)
    print(json.dumps(stats, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
