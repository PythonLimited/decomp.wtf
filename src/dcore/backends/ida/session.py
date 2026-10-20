"""The IDA bridge: decomp.wtf as an MCP client of the user's IDA integration.

decomp.wtf spawns the same server the user's AI client talks to (`uvx ida-mcp stdio`,
set up with `uvx ida-hcli mcp install`; override with DECOMPNET_IDA_MCP), opens the
binary in a headless idalib worker, runs IDAPython sweeps through `execute_python` and
closes the database. Everything a sweep produces is cached on disk keyed by the
binary's sha256, so IDA is paid for once per file.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shlex
import shutil
import threading
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

AGENT = "decomp-wtf"


class IdaError(RuntimeError):
    """IDA couldn't be reached or a sweep failed; shown to the user as is."""


def command() -> list[str]:
    """The ida-mcp server command: DECOMPNET_IDA_MCP, or uvx/ida-mcp found on PATH."""
    if env := os.environ.get("DECOMPNET_IDA_MCP"):
        return shlex.split(env)
    if exe := shutil.which("ida-mcp"):
        return [exe, "stdio", f"--agent={AGENT}"]
    if uvx := shutil.which("uvx"):
        return [uvx, "ida-mcp", "stdio", f"--agent={AGENT}"]
    return []


def available() -> bool:
    return bool(command())


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ the session


class IdaSession:
    """One `ida-mcp stdio` process, driven synchronously from the app's threads."""

    def __init__(self, *, timeout: float = 900, ready_timeout: float = 120, log=print):
        self.timeout = timeout
        self.ready_timeout = ready_timeout
        self.log = log
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._session: ClientSession | None = None
        self._stop: asyncio.Event | None = None
        self._ready = threading.Event()
        self._error: BaseException | None = None

    def __enter__(self) -> "IdaSession":
        cmd = command()
        if not cmd:
            raise IdaError("IDA MCP isn't available: install it with `uvx ida-hcli mcp install`, "
                           "or point DECOMPNET_IDA_MCP at the server command")
        self._thread = threading.Thread(target=self._run, args=(cmd,), daemon=True, name="ida-mcp")
        self._thread.start()
        if not self._ready.wait(timeout=self.ready_timeout):
            raise IdaError(f"the IDA MCP server didn't start within {self.ready_timeout:g} seconds "
                           f"(is IDA installed and licensed?)")
        if self._error is not None:
            raise IdaError(f"the IDA MCP server failed to start: {self._error}")
        return self

    def _run(self, cmd: list[str]) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._main(cmd))
        except BaseException as e:  # fatal: surfaced to whoever waits on _ready or a call
            self._error = e
            self._ready.set()

    async def _main(self, cmd: list[str]) -> None:
        params = StdioServerParameters(command=cmd[0], args=cmd[1:], env=dict(os.environ))
        self._stop = asyncio.Event()
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                self._session = session
                self._ready.set()
                await self._stop.wait()

    def call(self, tool: str, args: dict, timeout: float | None = None) -> str:
        """Call one MCP tool; returns its text payload. Raises IdaError on tool errors."""
        if self._session is None or self._loop is None:
            raise IdaError(f"the IDA MCP server isn't running: {self._error or 'connection lost'}")
        fut = asyncio.run_coroutine_threadsafe(self._call(tool, args), self._loop)
        try:
            return fut.result(timeout if timeout is not None else self.timeout)
        except TimeoutError:
            fut.cancel()
            raise IdaError(f"IDA's {tool} timed out after {timeout or self.timeout:.0f}s") from None

    async def _call(self, tool: str, args: dict) -> str:
        result = await self._session.call_tool(tool, args)
        text = "\n".join(c.text for c in (result.content or []) if getattr(c, "text", None))
        if result.is_error:
            raise IdaError(f"IDA's {tool} failed: {_error_text(text)}")
        return text

    def close(self) -> None:
        if self._loop is not None and self._stop is not None:
            try:
                self._loop.call_soon_threadsafe(self._stop.set)
            except RuntimeError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=30)

    def __exit__(self, *exc) -> None:
        self.close()


def _error_text(text: str) -> str:
    """MCP tool errors arrive as a JSON blob or plain text; keep the readable part."""
    try:
        data = json.loads(text)
    except ValueError:
        return text.strip()[:600] or "no message"
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            inner = err.get("content") or []
            for item in inner if isinstance(inner, list) else []:
                if isinstance(item, dict) and item.get("text"):
                    return str(item["text"])[:600]
        for key in ("error", "message", "detail"):
            if isinstance(data.get(key), str):
                return data[key][:600]
    return text.strip()[:600] or "no message"


def _json(text: str) -> dict:
    try:
        data = json.loads(text)
    except ValueError:
        return {"raw": text}
    return data if isinstance(data, dict) else {"raw": text}


# ------------------------------------------------------------------ tool wrappers


def open_database(session: IdaSession, path: Path, timeout: float = 1800, log=print) -> dict:
    """Open a binary, or the user's existing .i64/.idb, in an idalib worker; returns the server's JSON answer."""
    if Path(path).suffix.lower() in (".i64", ".idb"):
        log(f"IDA: opening the existing database {Path(path).name} (no analysis needed)")
    else:
        log(f"IDA: opening {Path(path).name} (analysis can take a while on big binaries)")
    res = _json(session.call("open_database", {"path": str(path)}, timeout=timeout))
    if res.get("error") or res.get("status") == "error":
        raise IdaError(f"IDA couldn't open {Path(path).name}: {_error_text(json.dumps(res))}")
    if not res.get("instance_id") and "raw" in res:
        raise IdaError(f"IDA gave an unexpected answer to open_database: {res['raw'].strip()[:400]}")
    return res


def execute_python(session: IdaSession, code: str, timeout: float = 900) -> dict:
    """Run an IDAPython sweep; returns {"result", "stdout", "stderr"} from the worker."""
    res = _json(session.call("execute_python", {"code": code, "timeout": timeout}, timeout=timeout + 120))
    if "raw" in res:  # the server didn't answer with its usual JSON envelope
        return {"stdout": res["raw"], "stderr": "", "result": None}
    if res.get("error"):
        raise IdaError(f"the IDA sweep failed: {_error_text(json.dumps({'error': res['error']}))}")
    return res


def close_database(session: IdaSession) -> None:
    try:
        session.call("close_database", {}, timeout=180)
    except IdaError:
        pass  # the worker releasing its lease on process exit is enough
