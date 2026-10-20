"""Running the user's AI agents on a ROM project.

CLI agents (Claude Code, Codex, Antigravity CLI, opencode) run headless in a private working folder, connected
to this app's MCP endpoint and allowed to use only its tools. Each session works through a few functions
and exits; the runner starts a fresh one until the user stops it or nothing is left. Models reached with
an API key (DeepSeek, OpenRouter, a local Ollama, any OpenAI-compatible endpoint) run in a small built-in
tool loop instead. Everything the agents print is parsed into a readable live feed.

The prompt goes in on stdin, never on the command line: no length limit (Windows caps a command line at 32,767
characters, and the prompt with its guides and the user's instructions can be long) and nothing in it is parsed.
"""

from __future__ import annotations

import collections
import json
import os
import re
import shutil
import tempfile
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from . import tools
from ..core.engine import Engine

WIN = sys.platform == "win32"


class Fatal(RuntimeError):
    """A helper can't work until the user changes something (shown as the helper's error, not retried)."""


@dataclass
class Kind:
    id: str
    name: str
    command: str  # executable, "" for the built-in agent
    vendor: str
    install: dict[str, str]  # os -> command
    signin: str
    docs: str


KINDS = {
    "claude": Kind("claude", "Claude Code", "claude", "Anthropic",
                   {"unix": "curl -fsSL https://claude.ai/install.sh | bash",
                    "windows": "irm https://claude.ai/install.ps1 | iex"},
                   "Open a terminal, run `claude` and sign in with /login.", "https://docs.claude.com/en/docs/claude-code"),
    "codex": Kind("codex", "Codex CLI", "codex", "OpenAI",
                  {"unix": "npm install -g @openai/codex", "windows": "npm install -g @openai/codex"},
                  "Run `codex login` once in a terminal.", "https://github.com/openai/codex"),
    "antigravity": Kind("antigravity", "Antigravity CLI", "agy", "Google",
                        {"unix": "curl -fsSL https://antigravity.google/cli/install.sh | bash",
                         "windows": "irm https://antigravity.google/cli/install.ps1 | iex"},
                        "Open a terminal and run `agy` once to sign in.", "https://antigravity.google/docs/cli"),
    "opencode": Kind("opencode", "opencode", "opencode", "any provider (DeepSeek, Qwen, Kimi, ...)",
                     {"unix": "curl -fsSL https://opencode.ai/install | bash", "windows": "npm install -g opencode-ai"},
                     "Run `opencode auth login` once to add a provider (DeepSeek, OpenRouter, ...).", "https://opencode.ai"),
    "api": Kind("api", "API key", "", "DeepSeek, OpenRouter, Ollama, any OpenAI-compatible API", {}, "",
                "https://api-docs.deepseek.com"),
}

API_PRESETS = {
    "deepseek": {"name": "DeepSeek", "base_url": "https://api.deepseek.com/v1", "model": "deepseek-chat", "key": True},
    "openrouter": {"name": "OpenRouter", "base_url": "https://openrouter.ai/api/v1", "model": "deepseek/deepseek-chat", "key": True},
    "ollama": {"name": "Ollama (local)", "base_url": "http://127.0.0.1:11434/v1", "model": "qwen3-coder", "key": False},
    "lmstudio": {"name": "LM Studio (local)", "base_url": "http://127.0.0.1:1234/v1", "model": "local-model", "key": False},
    "llamacpp": {"name": "llama.cpp (local)", "base_url": "http://127.0.0.1:8080/v1", "model": "local", "key": False},
    "openai": {"name": "OpenAI", "base_url": "https://api.openai.com/v1", "model": "gpt-5", "key": True},
    "custom": {"name": "Custom", "base_url": "", "model": "", "key": True},
}
# Google retired Gemini CLI on 2026-06-18; Antigravity CLI (`agy`) replaced it. Helpers and launcher choices saved
# by older versions as "gemini" carry on as Antigravity.
ALIASES = {"gemini": "antigravity", "agy": "antigravity"}

# decomp.wtf's tools are loaded up front in Antigravity (tools.ALWAYS_LOAD) and need no permission. Should a helper
# reach one through agy's generic MCP dispatcher instead, a headless run can't ask, and agy quietly refuses it:
# this rule in the user's agy settings allows decomp.wtf's tools (and nothing else).
AGY_ALLOW = "mcp(decomp/*)"

# Functions per helper session: a fresh session starts with a small, clean context (each function's assembly,
# drafts and diffs would otherwise ride along into the next one): cheaper per call, and the model stays sharp.
PER_SESSION = 1
# No stdout *and* no stderr for this long while a run is alive and none of this agent's tool
# calls is running inside the app: the model's stream has stalled (the provider's socket died
# mid-message). Silence with a tool in flight is legitimate (a compile, the first IDA fetch).
STALL_SECONDS = 300
# A model server that stops answering is a server problem, not the agent's: local servers (LM Studio,
# llama.cpp, ollama) go quiet for minutes while a model loads or swaps. Transport errors get their own
# backoff ladder and grace — and never count toward the three-strike stop.
SERVER_DOWN_BACKOFF = (15.0, 30.0, 60.0)
SERVER_DOWN_GRACE = 30 * 60


def kind_id(kind: str) -> str:
    return ALIASES.get(kind, kind)


def agy_settings() -> Path:
    return Path.home() / ".gemini" / "antigravity-cli" / "settings.json"


def endpoint_entry(e: dict) -> dict:
    """A saved API endpoint, with what's left out filled in from its provider (a name: the provider's, or for a
    custom server the address's host, so sessions say which machine they run on)."""
    provider = e.get("provider") if e.get("provider") in API_PRESETS else "custom"
    preset = API_PRESETS[provider]
    base = (e.get("base_url") or preset["base_url"]).strip()
    host = re.sub(r"^\w+://", "", base).split("/", 1)[0]
    moved = provider == "custom" or base.rstrip("/") != preset["base_url"].rstrip("/")  # Ollama on another box...
    out = {"id": str(e.get("id") or ""), "provider": provider, "base_url": base,
           "model": (e.get("model") or preset["model"]).strip(),
           "name": (e.get("name") or "").strip() or (host if moved and host else preset["name"]) or "API"}
    for k in ("api_key", "context_tokens", "max_sessions"):
        if e.get(k):
            out[k] = e[k]
    return out


def is_local(base: str, resolve: bool = True) -> bool:
    """An address on this computer or the local network (a llama.cpp box, Ollama on another machine): a private,
    loopback, link-local or Tailscale address, a name without dots or under .local/.lan/.internal/.home.arpa, or
    (`resolve`) a name that resolves to such addresses only."""
    import ipaddress
    import socket

    host = re.sub(r"^\w+://", "", base.strip()).split("/", 1)[0].rsplit("@", 1)[-1]
    host = host[1:].split("]", 1)[0] if host.startswith("[") else host.split(":", 1)[0] if host.count(":") == 1 else host
    if not host:
        return False

    def private(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        tailscale = a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10")
        return a.is_private or a.is_loopback or a.is_link_local or tailscale or a.is_unspecified

    if private(host):
        return True
    if "." not in host or re.search(r"\.(local|lan|home|internal|localdomain|home\.arpa)$", host, re.I) \
            or host.lower() == "localhost":
        return True
    if not resolve or re.fullmatch(r"[\d.]+|[0-9a-fA-F:]+", host):
        return False
    try:
        addrs = {i[4][0] for i in socket.getaddrinfo(host, None)}
    except (OSError, UnicodeError):
        return False
    return bool(addrs) and all(private(a) for a in addrs)


# what an agent CLI says when nobody signed in to it (Claude Code: "Not logged in · Please run /login")
_SIGNED_OUT = re.compile(r"not logged in|run /login|invalid api key|not authenticated|please (?:log|sign) ?in|"
                         r"auth(?:entication)? method", re.I)
# what a model's provider says when the account has no credit left (DeepSeek: "Insufficient Balance", OpenAI:
# "insufficient_quota", Anthropic: "credit balance is too low"): trying again can't help until it's topped up
_NO_CREDIT = re.compile(r"insufficient[ _](?:balance|credits?|funds|quota)|exceeded your current quota|"
                        r"credit balance is too low|payment required|out of credits?", re.I)
# and when it's asked too much at once (HTTP 429): it works again in a while
_THROTTLED = re.compile(r"too many requests|rate[ _-]?limit|concurrency limit|\b429\b|overloaded", re.I)


def no_credit(said: str) -> str | None:
    """The helper's error when its model's provider says the account is out of credit, else None."""
    if not (m := _NO_CREDIT.search(said)):
        return None
    return (f"the model's provider says the account is out of credit (\u201c{m.group(0)}\u201d): top it up, then "
            "start the agents again")


_versions: dict[str, tuple[float, str | None]] = {}
_models: dict[str, tuple[float, list[dict]]] = {}

# Claude Code's aliases always point at Anthropic's latest model of each kind.
CLAUDE_MODELS = [("fable", "Fable", "Anthropic's most capable model"), ("opus", "Opus", "very capable"),
                 ("sonnet", "Sonnet", "fast and capable, cheaper"), ("haiku", "Haiku", "fastest, cheapest")]


def _codex_config() -> dict:
    """The user's Codex settings (~/.codex/config.toml, or $CODEX_HOME's)."""
    import tomllib

    home = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")
    try:
        return tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _config_model(kind: str) -> str | None:
    """The model the user set as default in the agent's own settings, if any."""
    home = Path.home()
    try:
        if kind == "claude":
            return json.loads((home / ".claude" / "settings.json").read_text(encoding="utf-8")).get("model") or None
        if kind == "codex":
            return _codex_config().get("model") or None
        if kind == "antigravity":
            return json.loads(agy_settings().read_text(encoding="utf-8")).get("model") or None
        if kind == "opencode":
            base = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")
            return json.loads((base / "opencode" / "opencode.json").read_text(encoding="utf-8")).get("model") or None
    except (OSError, ValueError, AttributeError):
        return None
    return None


def models(kind: str, path: str | None) -> list[dict]:
    """Models to offer for this agent: [{"id", "name", "note"}]. Claude Code's aliases; opencode's and Antigravity's
    own lists (what the user's sign-in offers); for Codex the user's default plus any model name they type."""
    if kind == "claude":
        return [{"id": i, "name": n, "note": note} for i, n, note in CLAUDE_MODELS]
    if kind not in ("opencode", "antigravity") or not path:
        return []
    cached = _models.get(kind)
    if cached and time.time() - cached[0] < 600:
        return cached[1]
    try:
        res = subprocess.run(argv([path, "models"]), capture_output=True, text=True, encoding="utf-8", errors="replace",
                             stdin=subprocess.DEVNULL, timeout=30)
        lines = [line.strip() for line in res.stdout.splitlines()]
    except (OSError, subprocess.TimeoutExpired):
        lines = []
    if kind == "opencode":
        rows = [r for r in lines if re.fullmatch(r"[\w.-]+/[\w.:/-]+", r)]
        out = [{"id": r, "name": r.split("/", 1)[1], "note": r.split("/", 1)[0]} for r in rows[:200]]
    else:  # agy: "<slug>\t<name>" per model
        rows = [r.split("\t", 1) for r in lines if re.fullmatch(r"[\w.:-]+\t.+", r)]
        out = [{"id": slug, "name": name.strip(), "note": slug.split("-", 1)[0]} for slug, name in rows[:200]]
    _models[kind] = (time.time(), out)
    return out


def search_path() -> str | None:
    """Where to look for agents and npm (None: this process's PATH). On Windows also the PATH set for the user right
    now, read from the registry: an agent or Node.js installed while the app runs is found without restarting it."""
    if not WIN:
        return None
    import winreg

    dirs = os.environ.get("PATH", "").split(os.pathsep)
    for root, key in ((winreg.HKEY_CURRENT_USER, "Environment"),
                      (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")):
        try:
            with winreg.OpenKey(root, key) as k:
                dirs += [os.path.expandvars(d) for d in str(winreg.QueryValueEx(k, "Path")[0]).split(";")]
        except OSError:
            pass
    return os.pathsep.join(dict.fromkeys(d for d in dirs if d))


def _which(cmd: str) -> str | None:
    found = shutil.which(cmd, path=search_path())
    if found:
        return found
    home = Path.home()
    dirs = [home / ".local" / "bin", home / ".claude" / "local", home / ".opencode" / "bin", home / ".npm-global" / "bin"]
    if WIN and os.environ.get("APPDATA"):
        dirs.append(Path(os.environ["APPDATA"]) / "npm")  # npm's global installs on Windows
    if WIN and os.environ.get("LOCALAPPDATA"):
        dirs.append(Path(os.environ["LOCALAPPDATA"]) / "agy" / "bin")  # where Antigravity's installer puts agy
    # on Windows the file without an extension next to npm's foo.cmd is a shell script Windows can't run
    names = (f"{cmd}.exe", f"{cmd}.cmd") if WIN else (cmd, f"{cmd}.cmd", f"{cmd}.exe")
    for d in dirs:
        for name in names:
            if (d / name).exists():
                return str(d / name)
    return None


# npm's Windows launcher (cmd-shim) ends with: "%_prog%" [node options] "%dp0%\node_modules\...\cli.js" %*
_NPM_SHIM = re.compile(r'"%_prog%"\s+(?P<opts>[^"\r\n]*?)\s*"%~?dp0%?\\(?P<script>[^"\r\n]+)"\s+%\*', re.I)


def argv(cmd: list[str]) -> list[str]:
    """The command to start, as Windows needs it. npm installs agents there as .cmd scripts, which run through cmd.exe:
    it cuts an argument at its first line break (a prompt loses everything after its first line, and the flags after
    it with it) and treats & | < > in it as commands. Start node with the agent's script instead, as the .cmd would."""
    if not WIN or Path(cmd[0]).suffix.lower() not in (".cmd", ".bat"):
        return cmd
    shim = Path(cmd[0])
    try:
        m = _NPM_SHIM.search(shim.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        m = None
    if not m:
        return cmd
    script = shim.parent / m["script"]
    node = shim.parent / "node.exe"
    node = str(node) if node.exists() else shutil.which("node", path=search_path())
    if not node or not script.exists():
        return cmd
    return [node, *m["opts"].split(), str(script), *cmd[1:]]


def signin(k: Kind) -> str:
    """How to sign in to an agent, said for where decomp.wtf runs (WSL/Docker: in decomp.wtf's own terminal)."""
    from ..core import hostenv

    if not k.signin or hostenv.runtime() == "native":
        return k.signin
    text = k.signin.removeprefix("Open a terminal, ").removeprefix("Open a terminal and ")
    return f"{hostenv.terminal_hint()}, then: {text[0].lower()}{text[1:]}"


def detect() -> list[dict]:
    out = []
    for k in KINDS.values():
        row = {"id": k.id, "name": k.name, "vendor": k.vendor, "signin": signin(k), "docs": k.docs,
               "install": k.install.get("windows" if WIN else "unix", "")}
        if not k.command:
            row.update(installed=True, version=None, path=None)
        else:
            path = _which(k.command)
            cached = _versions.get(k.id)
            if path and (cached is None or time.time() - cached[0] > 300):
                try:
                    res = subprocess.run(argv([path, "--version"]), capture_output=True, text=True, encoding="utf-8",
                                         errors="replace", timeout=15)
                    version = (res.stdout or res.stderr).strip().splitlines()[0][:60] if (res.stdout or res.stderr).strip() else None
                except (OSError, subprocess.TimeoutExpired):
                    version = None
                _versions[k.id] = (time.time(), version)
            row.update(installed=path is not None, path=path, version=_versions.get(k.id, (0, None))[1] if path else None)
            if path:
                row.update(models=models(k.id, path), default_model=_config_model(k.id))
        if row["install"].startswith("npm ") and not row["installed"] and not shutil.which("npm", path=search_path()):
            row["needs"] = "Node.js (https://nodejs.org) for npm"
        elif k.id == "claude" and WIN and not shutil.which("git", path=search_path()):
            row["needs"] = "Git for Windows (https://git-scm.com/downloads/win): Claude Code needs its Git Bash"
        out.append(row)
    return out


# ---------------------------------------------------------------------------------- output parsing

def _tool_name(name: str) -> str:
    for prefix in ("mcp__decomp__", "mcp_decomp_", "decomp_agent.", "decomp_agent__", "decomp__", "decomp_", "decomp."):
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def _args_brief(args) -> str:
    if not isinstance(args, dict):
        return ""
    parts = []
    for k, v in args.items():
        if k == "source":
            parts.append(f"{len(str(v).splitlines())} lines of C")
        elif isinstance(v, str):
            parts.append(v if len(v) < 40 else v[:37] + "…")
        elif v not in (None, "", {}):
            parts.append(str(v))
    return ", ".join(parts)


_DECOMP_JS_CALL = re.compile(
    r"tools\s*\??\s*(?:\.\s*decomp|\[\s*[\"']decomp[\"']\s*\])\s*"
    r"(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*[\"']([A-Za-z_$][\w$]*)[\"']\s*\])\s*\(")
_JS_TEMPLATE = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(`(?:[^`\\]|\\.)*`)", re.S)


def _text_brief(text: str, n: int = 70) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[:n - 1] + "…"


def _js_first_arg(code: str, i: int, limit: int = 400) -> str:
    """A JS call's first argument from `code[i:]` (i is just after the `(`): balanced over brackets,
    quotes and template literals, cut at the top-level comma or closing paren."""
    depth, j, out = 0, i, []
    while j < len(code) and len(out) < limit:
        c = code[j]
        if c in "'\"`":
            q, k, buf = c, j + 1, []
            while k < len(code):
                if code[k] == "\\":
                    buf.append(code[k:k + 2])
                    k += 2
                    continue
                if code[k] == q or (code[k] == "\n" and q != "`"):
                    break
                buf.append(code[k])
                k += 1
            out.append(q + "".join(buf) + q)
            j = k + 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif c == "," and depth == 0:
            break
        out.append(c)
        j += 1
    return "".join(out).strip()


def _js_args_brief(raw: str, templates: dict[str, str] | None = None) -> str:
    """JS call arguments as a feed line: an object shows its fields, `source` reports its size."""
    text = (raw or "").strip()
    if text.startswith("{"):
        parts = []
        for m in re.finditer(r"([A-Za-z_$][\w$]*)\s*:\s*"
                             r"(`(?:[^`\\]|\\.)*`|\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|[^,}\n]*)", text):
            k, v = m.group(1), m.group(2).strip().strip("`\"'")
            if k == "source":
                body = (templates or {}).get(v) or v
                body = body.strip().strip("`").strip()
                n = len(body.splitlines()) or 1
                parts.append(f"source: {n} line{'s' if n != 1 else ''}")
            else:
                parts.append(f"{k}: " + (v if len(v) <= 60 else v[:57] + "…"))
            if len(parts) >= 4:
                break
        if parts:
            return ", ".join(parts)
    return _text_brief(text)


def _tool_lines(name: str, args) -> list[str]:
    """Feed line(s) for one tool call. opencode v2 reaches MCP servers through its JS sandbox: the
    event is its built-in `execute` tool carrying a script, and the decomp calls are inside it — show
    those calls (up to three) instead of the script."""
    if _tool_name(name) == "execute":
        code = ""
        if isinstance(args, dict):
            code = str(args.get("code") or args.get("script") or "")
            if not code:  # the script under some other single field name: treat it as one
                strings = [v for v in args.values() if isinstance(v, str) and len(v) > 15]
                code = strings[0] if len(strings) == 1 else ""
        elif isinstance(args, str):
            code = args
        if code.strip():
            templates = {m.group(1): m.group(2) for m in _JS_TEMPLATE.finditer(code)}
            lines = [f"{m.group(1) or m.group(2)}({_js_args_brief(_js_first_arg(code, m.end()), templates)})"
                     for m in list(_DECOMP_JS_CALL.finditer(code))[:3]]
            if lines:
                return lines
            return [f"execute({_text_brief(code.strip().splitlines()[0])})"]
    return [f"{_tool_name(name)}({_args_brief(args)})"]


def _error_text(err) -> str:
    """The message in an agent's error object, whatever its shape (opencode nests it under data)."""
    if isinstance(err, dict):
        data = err.get("data") if isinstance(err.get("data"), dict) else {}
        msg = err.get("message") or data.get("message") or ""
        name = err.get("name") or err.get("type") or ""
        if msg and name and name not in ("UnknownError", "Error") and name not in msg:
            return f"{name}: {msg}"
        return str(msg or name or json.dumps(err)[:300])
    return str(err or "")


def _parse_agy(obj: dict, state: dict) -> list[tuple[str, str]]:
    """Antigravity CLI's stream-json: step_update events (text arrives in deltas, gathered per step) and a result."""
    out: list[tuple[str, str]] = []
    ev = obj.get("event")
    if ev == "step_update" and isinstance(obj.get("step_update"), dict):
        st = obj["step_update"]
        step, kind = st.get("step_index"), st.get("step_type")
        if kind in ("agent_response", "thinking", "planner_response"):
            texts = state.setdefault("agy_text", {})
            texts[step] = texts.get(step, "") + str(st.get("text_delta") or "")
            if st.get("state") == "DONE" and texts.get(step, "").strip():
                out.append(("think" if kind == "thinking" else "text", texts.pop(step).strip()))
        elif kind == "tool" and st.get("state") == "ACTIVE" and step not in state.setdefault("agy_tools", set()):
            state["agy_tools"].add(step)
            info = st.get("tool_info") if isinstance(st.get("tool_info"), dict) else {}
            name, params = info.get("name") or st.get("tool_name") or "", info.get("parameters")
            if name == "call_mcp_tool" and isinstance(params, dict):  # agy reaches MCP tools through one dispatcher
                name, params = params.get("ToolName") or name, params.get("Arguments")
            out.append(("tool", f"{_tool_name(name)}({_args_brief(params)})"))
    elif ev == "result" and isinstance(obj.get("result"), dict):
        res = obj["result"]
        usage = res.get("usage") if isinstance(res.get("usage"), dict) else {}
        if usage.get("total_tokens"):
            out.append(("usage", json.dumps({"tokens": usage["total_tokens"]})))
        denied = [d for d in res.get("denied_actions") or [] if isinstance(d, dict)]
        if any(d.get("action") == "mcp" for d in denied):
            out.append(("error", f"Antigravity refused decomp.wtf's tools: a background run can't ask you for permission. "
                                 f"Allow them once: add \"{AGY_ALLOW}\" to \"permissions\": {{\"allow\": [...]}} in "
                                 f"{agy_settings()} (only decomp.wtf's tools; shell, files and the web keep asking)."))
        if res.get("status") not in (None, "SUCCESS"):
            out.append(("error", str(res.get("error") or f"session ended: {res.get('status')}")[:400]))
        else:
            turns = res.get("num_turns")
            out.append(("info", "session finished" + (f" ({turns} turns)" if turns else "")))
    elif ev == "error":
        out.append(("error", _error_text(obj.get("error") or obj.get("message"))[:400]))
    return out


def clean_stderr(kind: str, line: str) -> str:
    """One line of an agent's stderr as worth showing, or "" for noise."""
    line = line.strip()
    if kind == "opencode" and "level=" in line:  # opencode --print-logs: keep the error itself, drop stack noise
        m = re.search(r'\berror="((?:[^"\\]|\\.)*)"', line)
        return m.group(1).replace('\\"', '"') if m and "level=ERROR" in line else ""
    if line.startswith("AGY_ERROR:"):  # agy: a structured error line
        try:
            return _error_text(json.loads(line.split(":", 1)[1]))[:300]
        except ValueError:
            return line
    return line


def parse_line(kind: str, line: str, state: dict | None = None) -> list[tuple[str, str]]:
    """(type, text) items for the live feed from one line of agent output: text, think, tool, info, error, usage.
    `state` carries what spans lines (Antigravity streams text in pieces) for one session."""
    line = line.strip()
    if not line:
        return []
    try:
        obj = json.loads(line)
    except ValueError:
        return [("info", line[:400])]
    if not isinstance(obj, dict):
        return []
    if "event" in obj and "type" not in obj:  # Antigravity CLI
        return [(k, v) for k, v in _parse_agy(obj, {} if state is None else state) if v]
    t = obj.get("type")
    out: list[tuple[str, str]] = []
    if t == "assistant" and isinstance(obj.get("message"), dict):  # Claude Code
        for c in obj["message"].get("content", []):
            if c.get("type") == "text" and c.get("text", "").strip():
                out.append(("text", c["text"].strip()))
            elif c.get("type") == "thinking" and c.get("thinking", "").strip():
                out.append(("think", c["thinking"].strip()))
            elif c.get("type") == "tool_use" and c.get("name") != "ToolSearch":  # ToolSearch: Claude Code loading tools
                out.append(("tool", f"{_tool_name(c.get('name', ''))}({_args_brief(c.get('input'))})"))
    elif t == "result":  # Claude Code end of session
        if obj.get("is_error") or obj.get("status") == "error":
            out.append(("error", str(obj.get("result") or obj.get("error") or "session failed")[:400]))
        else:
            cost = obj.get("total_cost_usd")
            turns = obj.get("num_turns")
            bits = [f"{turns} turns" if turns else "", f"${cost:.2f}" if isinstance(cost, (int, float)) else ""]
            out.append(("info", "session finished" + (f" ({', '.join(b for b in bits if b)})" if any(bits) else "")))
            if isinstance(cost, (int, float)):
                out.append(("usage", json.dumps({"usd": cost})))
            stats = obj.get("stats") if isinstance(obj.get("stats"), dict) else {}
            if stats.get("total_tokens"):
                out.append(("usage", json.dumps({"tokens": stats["total_tokens"]})))
    elif t in ("item.started", "item.completed") and isinstance(obj.get("item"), dict):  # Codex
        item = obj["item"]
        it = item.get("type") or item.get("item_type")
        if it == "agent_message" and t == "item.completed":
            out.append(("text", str(item.get("text", "")).strip()))
        elif it == "reasoning" and t == "item.completed" and item.get("text"):
            out.append(("think", str(item["text"]).strip()))
        elif it == "mcp_tool_call" and t == "item.started":
            out.append(("tool", f"{_tool_name(item.get('tool', ''))}({_args_brief(item.get('arguments'))})"))
        elif it == "command_execution" and t == "item.started":
            out.append(("tool", f"shell: {str(item.get('command', ''))[:80]}"))
        elif it == "error":
            out.append(("error", str(item.get("message", ""))[:400]))
    elif t == "turn.completed":
        out.append(("info", "turn finished"))
        usage = obj.get("usage") if isinstance(obj.get("usage"), dict) else {}
        tokens = sum(v for k, v in usage.items() if k in ("input_tokens", "output_tokens") and isinstance(v, int))
        if tokens:
            out.append(("usage", json.dumps({"tokens": tokens})))
    elif t in ("error", "turn.failed"):  # Codex; opencode: {"error": {"name", "data": {"message"}}}
        text = _error_text(obj.get("error") or obj.get("message"))
        if not text.startswith("Unexpected server error"):  # opencode's placeholder: its log line says what failed
            out.append(("error", text[:400]))
    elif t == "tool_use":  # opencode
        part = obj.get("part") if isinstance(obj.get("part"), dict) else obj
        name = part.get("tool_name") or part.get("tool") or part.get("name") or ""
        args = part.get("parameters") or (part.get("state") or {}).get("input") or part.get("input")
        out += [("tool", text) for text in _tool_lines(name, args)]
    elif t == "text" and isinstance(obj.get("part"), dict):  # opencode
        text = obj["part"].get("text", "").strip()
        if text:
            out.append(("text", text))
    elif t in ("step_finish", "step-finish") and isinstance(obj.get("part"), dict):  # opencode: cost per step
        part = obj["part"]
        if isinstance(part.get("cost"), (int, float)) and part["cost"]:
            out.append(("usage", json.dumps({"usd": part["cost"]})))
    return [(k, v) for k, v in out if v]


# ---------------------------------------------------------------------------------- sessions

@dataclass
class Session:
    id: str
    kind: str
    label: str
    slug: str
    agent_name: str
    options: dict
    state: str = "starting"  # starting | working | waiting | stopped | error
    started_at: float = field(default_factory=time.time)
    runs: int = 0
    error: str = ""
    feed: collections.deque = field(default_factory=lambda: collections.deque(maxlen=400))
    seq: int = 0
    stop: threading.Event = field(default_factory=threading.Event)
    proc: subprocess.Popen | None = None
    usd: float = 0.0  # what the agent's provider charged, as the agent reports it
    tokens: int = 0
    signed_out: bool = False  # the agent CLI isn't signed in: trying again won't help
    throttled: bool = False  # the last run ended on the provider's limit of requests at once: not a failure
    server_down: bool = False  # the model server (api kind) stopped answering: patience, not a strike
    server_since: float | None = None  # when the current server-down stretch started (the grace clock)
    server_retries: int = 0  # consecutive server-down waits (drives the backoff ladder)

    def push(self, kind: str, text: str) -> None:
        self.seq += 1
        self.feed.append({"seq": self.seq, "t": time.time(), "type": kind, "text": text[:4000]})

    def snapshot(self, since: int = 0) -> dict:
        return {"id": self.id, "kind": self.kind, "label": self.label, "slug": self.slug, "agent": self.agent_name,
                "state": self.state, "runs": self.runs, "error": self.error, "started_at": self.started_at,
                "model": self.options.get("model") or "", "usd": round(self.usd, 4), "tokens": self.tokens,
                "feed": [f for f in self.feed if f["seq"] > since]}


# The session's OS-level fence (macOS): allow everything, then deny the paths an agent must never
# learn to read — the app's home (db, logs, registry, projects), the repo, the game's own files
# (exe/pdb/i64: the tools serve what they hold) and the obvious credential stores. Paired with the
# prompt contract: answers come from the tools, never from poking the machine's filesystem.
_FENCED_PATHS = ("decomp-home", "Desktop", "Downloads", "Library/Keychains", ".ssh", ".aws",
                 ".config/gcloud", ".docker")


def session_fence() -> str:
    """The sandbox-exec profile for one agent session (see _FENCED_PATHS)."""
    home = Path.home()
    deny = " ".join(f'(subpath "{home / p}")' for p in _FENCED_PATHS)
    return f'(version 1)\n(allow default)\n(deny file-read* file-write* {deny})\n'


class Manager:
    def __init__(self, net: Engine, home: Path, mcp_url: str):
        self.net, self.home, self.mcp_url = net, home, mcp_url
        self.sessions: dict[str, Session] = {}
        self.assignments: dict[int, str] = {}  # agent id -> project slug
        self._lock = threading.Lock()
        self.on_stop = lambda: None  # set by the server: close tunnels when the app quits
        self.persist = lambda running: None  # set by the server: remember helpers to resume after a restart

    # -- control

    def start(self, kind: str, slug: str, count: int = 1, options: dict | None = None) -> list[str]:
        options = dict(options or {})
        if kind_id(kind) != kind:
            kind = kind_id(kind)
            options.pop("model", None)  # a Gemini CLI model name may mean nothing to Antigravity: use its default
        if kind not in KINDS:
            raise ValueError(f"unknown agent kind {kind!r}")
        ids = []
        with self._lock:
            for _ in range(max(1, min(int(count), 8))):
                n = 1 + sum(1 for s in self.sessions.values() if s.kind == kind)
                sid = f"{kind}-{n}"
                while sid in self.sessions:
                    n += 1
                    sid = f"{kind}-{n}"
                if kind == "api":  # numbered per endpoint: "gpu-box #2" says which machine it runs on
                    name = options.get("provider_name") or "API"
                    k = 1 + max((int(s.label.rsplit(" #", 1)[1]) for s in self.sessions.values() if s.kind == "api"
                                 and s.label.rsplit(" #", 1)[0] == name and s.label.rsplit(" #", 1)[-1].isdigit()), default=0)
                    label = f"{name} #{k}"
                else:
                    label = f"{KINDS[kind].name} #{n}"
                s = Session(sid, kind, label, slug, sid, dict(options))
                self.sessions[sid] = s
                threading.Thread(target=self._run, args=(s,), daemon=True, name=f"agent-{sid}").start()
                ids.append(sid)
        self.persist(self.running())
        return ids

    def running(self) -> list[dict]:
        """The helpers that should keep working: resumed by the server after the app restarts."""
        return [{"kind": s.kind, "slug": s.slug, "options": {k: v for k, v in s.options.items() if k != "api_key"}}
                for s in self.sessions.values() if s.state in ("starting", "working", "waiting") and not s.stop.is_set()]

    def stop(self, sid: str | None = None) -> None:
        """Stop one helper (for good) or all of them (the app is quitting: they resume next time)."""
        for s in list(self.sessions.values()):
            if sid in (None, s.id):
                s.stop.set()
                if s.proc and s.proc.poll() is None:
                    _terminate(s.proc)
                if s.state not in ("error",):
                    s.state = "stopped"
                self._release_claims(s)
        if sid is not None:
            self.persist(self.running())

    def _release_claims(self, s: Session) -> None:
        """Hand back whatever this session still holds. The _run thread releases at its end too,
        but the quit path exits the process about half a second after the stop flag is set - long
        before a dying agent's reader thread gets there - so releases also happen here, synchronously,
        wherever a session is stopped."""
        freed = self.net.release_claims(s.agent_name, s.slug)
        if freed:
            s.push("info", f"released {len(freed)} claim(s): " + ", ".join(freed[:3]) + ("…" if len(freed) > 3 else ""))

    def remove(self, sid: str) -> None:
        self.stop(sid)
        self.sessions.pop(sid, None)

    def snapshot(self, since: dict | None = None) -> list[dict]:
        since = since or {}
        return [s.snapshot(int(since.get(s.id, 0))) for s in self.sessions.values()]

    def project_of(self, agent_id: int) -> str | None:
        return self.assignments.get(agent_id)

    # -- loop

    def _progress(self, agent_id: int) -> int:
        """Compiles + claims + notes by this agent: a session that adds none of these made no progress."""
        row = self.net.store.one(
            "SELECT (SELECT COUNT(*) FROM attempts WHERE agent_id=?) + (SELECT COUNT(*) FROM events WHERE agent_id=?) AS n",
            agent_id, agent_id)
        return row["n"]

    def _left(self, slug: str) -> int:
        proj = self.net.project_row(slug)
        row = self.net.store.one("SELECT COUNT(*) AS n FROM functions WHERE project_id=? AND status='open' "
                                 "AND mode='decompile'", proj["id"])
        return row["n"]

    def _claimable(self, slug: str, agent_id: int) -> int:
        """Open functions this agent could claim right now: not another helper's claim, and not one it
        itself gave up on (claim_row's picker skips functions the agent released)."""
        proj = self.net.project_row(slug)
        row = self.net.store.one(
            "SELECT COUNT(*) AS n FROM functions f WHERE f.project_id=? AND f.status='open' "
            "AND f.mode='decompile' "
            "AND f.id NOT IN (SELECT function_id FROM claims WHERE agent_id != ?) "
            "AND f.name NOT IN (SELECT detail FROM events WHERE project_id=? AND agent_id=? AND kind='release')",
            proj["id"], agent_id, proj["id"], agent_id)
        return row["n"]

    def _account(self, s: Session, usage: dict) -> None:
        """Add what a session spent to the session and to the project (kept in its config across restarts)."""
        usd, tokens = float(usage.get("usd") or 0), int(usage.get("tokens") or 0)
        s.usd += usd
        s.tokens += tokens
        self.net.add_spend(s.slug, usd, tokens)

    def over_budget(self, slug: str) -> float | None:
        """The budget (USD) when the project's agents have spent it, else None."""
        cap = self.budget()
        spent = (self.net.spend(slug) or {}).get("usd", 0)
        return cap if cap and spent >= cap else None

    def budget(self) -> float:
        return 0.0  # set by the server from the settings

    def _run(self, s: Session) -> None:
        agent, token = self.net.local_agent(s.agent_name)
        self.assignments[agent.id] = s.slug
        # scratch, not state: nothing walkable from here reaches the app's home (the database,
        # server.json, the logs) or the project folder with its caches - an agent that explores
        # its parents finds only our scratch root
        workdir = Path(tempfile.gettempdir()) / "decomp-agents" / s.id
        workdir.mkdir(parents=True, exist_ok=True)
        failures = throttles = 0
        s.push("info", f"{s.label} starting on {s.slug}")
        while not s.stop.is_set():
            if self._left(s.slug) == 0:
                s.push("info", "nothing left to decompile here 🎉")
                break
            if self._claimable(s.slug, agent.id) == 0:
                with self.net.store.tx() as db:  # a helper that died mid-claim must not stall the rest
                    self.net._expire_claims(db)
            if self._claimable(s.slug, agent.id) == 0:
                # Everything open belongs to other helpers (or was released by this one): idle, not a
                # failure — a session that finds nothing to claim must not eat the three-strike stop.
                if s.state != "waiting" or not s.feed or "none claimable" not in s.feed[-1]["text"]:
                    s.push("info", f"waiting: {self._left(s.slug)} function(s) still open, none claimable right now")
                s.state = "waiting"
                s.stop.wait(10)
                continue
            if (cap := self.over_budget(s.slug)) is not None:
                s.push("info", f"stopping: the agents on this project have spent the ${cap:.2f} budget (Setup)")
                break
            s.state = "working"
            s.runs += 1
            t0 = time.time()
            before = self._progress(agent.id)
            try:
                ok = self._run_with_lease(s, agent, token, workdir)
            except Fatal as e:  # needs the user first: retrying can't help
                s.state, s.error = "error", str(e)
                break
            except Exception as e:  # keep the runner alive; show what happened
                s.push("error", f"{type(e).__name__}: {e}")
                ok = False
            if ok and not s.stop.is_set() and self._progress(agent.id) == before:
                s.error = "the session ended without compiling anything (check the agent's output)"
                s.push("error", s.error)
                ok = False
            if s.stop.is_set():
                break
            if s.signed_out:
                s.state = "error"
                break
            if ok:
                s.server_down, s.server_since, s.server_retries = False, None, 0
            elif s.server_down:
                wait = self._server_down_wait(s)
                if wait is None:
                    break  # patience ran out: _server_down_wait set the error state
                s.state = "waiting"
                s.stop.wait(wait)
                continue
            if s.throttled and throttles < 10:  # the provider's limit, not the agent's failure: wait it out
                s.throttled, throttles = False, throttles + 1
                s.state = "waiting"
                s.push("info", "the model's provider says too many requests at once: trying again in a minute "
                               "(fewer agents at once on this account would wait less)")
                s.stop.wait(60)
                continue
            throttles = 0 if ok else throttles
            failures = 0 if ok else failures + 1
            if failures >= 3:
                s.state = "error"
                s.error = s.error or "the agent failed three times in a row"
                # no sign-in hint here: real sign-in failures stop earlier with their own message, and
                # "run `opencode auth login`" on unrelated failures sent users chasing the wrong thing
                s.push("error", f"stopping: {s.error}")
                break
            s.state = "waiting"
            s.stop.wait(3 if ok else min(60, 5 * failures + max(0, 10 - (time.time() - t0))))
        if s.state != "error":
            s.state = "stopped"
        if not s.stop.is_set():  # finished by itself (done, budget, errors): no need to resume it
            s.stop.set()
            self.persist(self.running())
        self._release_claims(s)

    def _server_down_wait(self, s: Session) -> float | None:
        """The patience ladder while the model server is down: 15s, 30s, then 60s steady, for up to
        SERVER_DOWN_GRACE in total. None means patience ran out (state and error are set here): the
        server really isn't coming back on its own."""
        if s.server_since is None:
            s.server_since = time.time()
        if time.time() - s.server_since > SERVER_DOWN_GRACE:
            s.state = "error"
            s.error = s.error or "the model server stopped answering"
            s.push("error", f"stopping: {s.error} (it didn't come back for {SERVER_DOWN_GRACE / 60:.0f} minutes)")
            return None
        wait = SERVER_DOWN_BACKOFF[min(s.server_retries, len(SERVER_DOWN_BACKOFF) - 1)]
        s.server_retries += 1
        s.push("info", f"the model server still isn't answering — retrying in {wait:.0f}s "
                       f"(it may be busy, stuck, or not running)")
        return wait

    def prompt(self, s: Session) -> str:
        text = self._prompt(s)
        # the know-how every session reads first, given up front (saves each session its first tool calls)
        ov = self.net.overview(s.slug)
        arch = ((ov.get("binary") or {}).get("arch") or "") if ov.get("kind") == "native" else ""
        topics = ["workflow", "x86" if arch in ("x86", "x86_64") else "aarch64"]
        text += "\nKnow-how you'd otherwise read with guide() (more topics: guide()):\n\n" + "\n\n".join(
            tools._guide(t) for t in topics)
        if (wish := self.net.instructions(s.slug)):
            text += f"\nThe user's instructions for this project (they come first):\n{wish}\n"
        return text

    def _prompt(self, s: Session) -> str:
        ov = self.net.overview(s.slug)
        arch = (ov.get("binary") or {}).get("arch") or ""
        guide = "x86" if arch in ("x86", "x86_64") else "aarch64"
        return tools.WORK_PROMPT.format(title=ov["title"], count=s.options.get("per_session", PER_SESSION), compiler_guide=guide)

    def _command(self, s: Session, token: str, workdir: Path) -> tuple[list[str], dict, str]:
        """The agent's command line, environment and what goes in on stdin (the prompt)."""
        k = KINDS[s.kind]
        exe = _which(k.command)
        if not exe:
            raise RuntimeError(f"{k.name} is not installed")
        env = dict(os.environ)
        if WIN:
            env["PATH"] = search_path()  # the agent finds node (and what it needs) even when installed after the app
        prompt = self.prompt(s)
        model = s.options.get("model") or ""
        if s.kind == "claude":
            cfg = workdir / "mcp.json"
            cfg.write_text(json.dumps({"mcpServers": {"decomp": {"type": "http", "url": self.mcp_url,
                                                                  "headers": {"Authorization": f"Bearer {token}"}}}}),
                           encoding="utf-8")
            cmd = [exe, "-p", "--output-format", "stream-json", "--verbose", "--mcp-config", str(cfg),
                   "--strict-mcp-config", "--allowedTools", "mcp__decomp", "--disallowedTools",
                   "Bash,Edit,Write,NotebookEdit,WebFetch,WebSearch"]
            if model:
                cmd += ["--model", model]
        elif s.kind == "codex":
            env["DECOMP_TOKEN"] = token
            # The worker's own server, under a name of its own: `-c` settings merge into the user's config, and
            # `decomp connect codex` gave that a stdio `decomp` entry (a url on top of it: "url is not supported for
            # stdio"). The user's MCP servers are switched off for the run, as --strict-mcp-config does for Claude.
            cmd = [exe, "exec", "--json", "--skip-git-repo-check", "--ephemeral", "-C", str(workdir), "-s", "read-only"]
            for name in (_codex_config().get("mcp_servers") or {}):
                if re.fullmatch(r"[A-Za-z0-9_-]+", name):
                    cmd += ["-c", f"mcp_servers.{name}.enabled=false"]
            cmd += ["-c", f'mcp_servers.decomp_agent={{url="{self.mcp_url}", bearer_token_env_var="DECOMP_TOKEN", '
                          'default_tools_approval_mode="approve", tool_timeout_sec=180}',
                    "-c", 'approval_policy="never"']
            if model:
                cmd += ["-m", model]
            cmd.append("-")  # the prompt comes from stdin
        elif s.kind == "antigravity":
            # the workspace's own MCP config; tool permission comes from the user's rule for decomp's tools (AGY_ALLOW)
            (workdir / ".agents").mkdir(exist_ok=True)
            (workdir / ".agents" / "mcp_config.json").write_text(json.dumps({"mcpServers": {"decomp": {
                "serverUrl": self.mcp_url, "headers": {"Authorization": f"Bearer {token}"}}}}), encoding="utf-8")
            # a session works through several functions: more than agy's default 5 minutes
            cmd = [exe, "--output-format", "stream-json", "--input-format", "stream-json", "--print-timeout", "2h"]
            if model:
                cmd += ["--model", model]
            prompt = json.dumps({"event": "user", "message": {"content": prompt}}) + "\n"
        elif s.kind == "opencode":
            # v2 config: MCP servers nest under mcp.servers, `codemode: false` keeps the decomp tools on
            # the model's native tool list (default Code Mode hides them inside a JS sandbox), and
            # permissions are an array with v2 action names (shell, not bash).
            # "deny" takes the tools out of the request, and OpenCode Zen's free models then refuse it ("can only be
            # used from within OpenCode"). "ask" keeps the usual tools, and `opencode run` rejects every ask itself.
            zen = (model or _config_model("opencode") or "opencode/").startswith("opencode/")
            never = "ask" if zen else "deny"
            (workdir / "opencode.json").write_text(json.dumps({
                "$schema": "https://opencode.ai/config.json",
                "mcp": {"servers": {"decomp": {"type": "remote", "url": self.mcp_url, "codemode": False,
                                               "headers": {"Authorization": f"Bearer {token}"}}}},
                "permissions": [{"action": "edit", "resource": "*", "effect": never},
                                {"action": "shell", "resource": "*", "effect": never},
                                {"action": "webfetch", "resource": "*", "effect": never}],
            }), encoding="utf-8")
            # --print-logs: opencode's JSON error only says "Unexpected server error"; the log line says what failed.
            # The level string is case-sensitive since opencode v2.0: "ERROR" is refused as a CLI error.
            # --standalone: a private server instead of the shared background daemon — daemon-hosted
            # sessions survive the app's stop and auto-resume when the service restarts, which is what
            # kept "killed" agents working (and ghosting for hours)
            cmd = [exe, "run", "--standalone", "--format", "json", "--print-logs", "--log-level", "error"]
            if model:
                cmd += ["-m", model]
            if sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").exists():
                cmd = ["/usr/bin/sandbox-exec", "-p", session_fence(), *cmd]
        else:
            raise RuntimeError(s.kind)
        return argv(cmd), env, prompt

    def _run_cli(self, s: Session, token: str, workdir: Path) -> bool:
        cmd, env, prompt = self._command(s, token, workdir)
        env["PWD"] = str(workdir)  # Popen's cwd doesn't touch PWD: opencode v2 resolves its project from it
        s.push("info", f"session {s.runs}: {KINDS[s.kind].name} started")
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if WIN else 0
        proc = subprocess.Popen(cmd, cwd=workdir, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", bufsize=1,
                                creationflags=flags, start_new_session=not WIN)
        s.proc = proc
        errors: collections.deque = collections.deque(maxlen=20)
        last = [time.time()]  # the watchdog's heartbeat: any line, either pipe, counts

        def feed_prompt():
            try:
                proc.stdin.write(prompt)
                proc.stdin.close()  # end of input: the agent works on this one prompt, then exits
            except OSError:  # it exited before reading (stderr says why)
                pass

        def drain_err():
            for line in proc.stderr:
                last[0] = time.time()
                if (text := clean_stderr(s.kind, line)) and (not errors or errors[-1] != text):
                    errors.append(text)
        threading.Thread(target=feed_prompt, daemon=True).start()
        threading.Thread(target=drain_err, daemon=True).start()

        def watch_stream():
            while proc.poll() is None and not s.stop.is_set():
                if time.time() - last[0] > STALL_SECONDS and not tools.tool_active(s.agent_name):
                    s.push("error", f"no output for {STALL_SECONDS // 60} minutes — the model's stream stalled; "
                                    "restarting the session (attempts and claims are saved)")
                    _terminate(proc)
                    return
                s.stop.wait(5)
        threading.Thread(target=watch_stream, daemon=True).start()

        saw_tool = False
        said: collections.deque = collections.deque(maxlen=20)
        state: dict = {}
        last_error = refused = ""
        for line in proc.stdout:
            last[0] = time.time()
            for kind, text in parse_line(s.kind, line, state):
                if kind == "usage":
                    self._account(s, json.loads(text))
                    continue
                saw_tool |= kind == "tool"
                said.append(text)
                if kind == "error":
                    last_error = text
                    refused = refused or (text if text.startswith("Antigravity refused") else "")
                s.push(kind, text)
            if s.stop.is_set():
                _terminate(proc)
                break
        code = proc.wait()
        s.proc = None
        if refused and not s.stop.is_set():
            raise Fatal(refused)  # every retry would be refused the same way
        if code != 0 and not s.stop.is_set() and (why := no_credit(" ".join([*said, *errors]))):
            raise Fatal(why)  # every agent on this account fails the same way until it's topped up
        if code != 0 and not s.stop.is_set() and _THROTTLED.search(" ".join([*said, *errors])):
            s.throttled = True
        if code != 0 and not s.stop.is_set() and _SIGNED_OUT.search(" ".join([*said, *errors])):
            s.signed_out = True
            s.error = f"{KINDS[s.kind].name} isn't signed in on this computer. {signin(KINDS[s.kind])}"
            s.push("error", s.error)
            return False
        if code != 0 and not s.stop.is_set():
            # The message, not the stack: stacks end in frames ("at ..."), so joining the *last*
            # stderr lines showed only frames (opencode's --log-level crash surfaced as pure
            # frames). Prefer the first error-looking line; fall back through the shapes.
            lines = [ln for ln in errors if not re.match(r"at [\w.<>]+ \(", ln)] or list(errors)
            head = next((ln for ln in lines
                         if re.search(r"(?i)error|invalid|refused|denied|failed|not found", ln)),
                        lines[0] if lines else "")
            tail = head or last_error or f"exited with code {code}"
            s.error = tail[:300]
            s.push("error", f"exited with code {code}: {tail[:600]}" if tail != f"exited with code {code}" else tail)
            return False
        if not saw_tool and not s.stop.is_set():
            s.error = "the agent never used the decomp tools" + (f": {list(errors)[-1]}" if errors else "")
            s.push("error", s.error)
            return False
        s.error = ""
        return True

    # -- built-in agent for OpenAI-compatible APIs

    def _run_with_lease(self, s: Session, agent, token: str, workdir: Path) -> bool:
        """API sessions can think for many minutes inside a single request; beat their claim so a
        long local generation does not lose the function. CLI agents renew on every tool call."""
        if s.kind != "api":
            return self._run_cli(s, token, workdir)
        stop = threading.Event()

        def beat() -> None:
            while not stop.wait(120):
                try:
                    self.net.renew_claims(agent, s.slug)
                except Exception:
                    pass

        threading.Thread(target=beat, name=f"lease-{s.id}", daemon=True).start()
        try:
            return self._run_api(s, agent)
        finally:
            stop.set()

    def _run_api(self, s: Session, agent) -> bool:
        """The agent loop for any OpenAI-compatible API. The conversation is kept within the model's context
        (`context_tokens`, or what a local llama.cpp server says it has): older tool output is trimmed first, and
        when the server still says it's too long, trimmed harder and sent again."""
        s.server_down = False  # only the transport-exhaustion path below sets it again
        base = (s.options.get("base_url") or "").rstrip("/")
        model = s.options.get("model") or ""
        if not base or not model:
            raise RuntimeError("set the API address and model first")
        headers = {"Content-Type": "application/json"}
        if s.options.get("api_key"):
            headers["Authorization"] = f"Bearer {s.options['api_key']}"
        schema = api_tool_schemas(native=bool(self.net.native_slug(s.slug)))
        messages = [{"role": "system", "content": tools.INSTRUCTIONS},
                    {"role": "user", "content": self.prompt(s)}]
        used_tool = False
        nudges = 0
        timeout = _api_timeout(base, s.options)  # per-chunk; local models get an hour of patience
        with httpx.Client(timeout=httpx.Timeout(timeout, connect=15)) as client:
            window = context_window(client, base, s.options)
            s.push("info", f"session {s.runs}: {model} via {base} ({window // 1000}K tokens of context)")
            budget = int(window * 0.7) - _tokens(schema)  # room for the reply and the tools' definitions
            for _step in range(int(s.options.get("max_steps", 120))):
                if s.stop.is_set():
                    return True
                reply = None
                attempt = trims = 0
                while trims < 4:
                    # local endpoints are free and (usually) roomy: eliding their old tool output makes
                    # them re-fetch the same disassembly in ever-smaller chunks; keep their history whole
                    trimmed = messages if is_local(base) else _trim_history(messages)
                    fit(trimmed, budget)
                    body: dict = {"model": model, "messages": trimmed, "tools": schema, "tool_choice": "auto"}
                    if s.options.get("max_tokens"):
                        body["max_tokens"] = int(s.options["max_tokens"])  # explicit cap; else the server's own applies
                    try:
                        reply = _completion(client, f"{base}/chat/completions", headers, body)
                        break
                    except _ModelServerError as e:
                        if _too_long(e):
                            if trims < 3:  # doesn't fit the model's context: trim harder and send again
                                trims += 1
                                budget = int(budget * 0.6)  # the server counts differently, or knows better
                                s.push("info", "the request doesn't fit the model's context: trimming the conversation "
                                               "and trying again")
                                continue
                            # out of trims: the server won't take it even trimmed down
                            s.error = ("the model's context is too small for this work even after trimming: give it at "
                                       "least 16K tokens (llama.cpp: -c 16384; Ollama: OLLAMA_CONTEXT_LENGTH=16384; LM "
                                       "Studio: Context Length) and set it in Agents & models")
                            s.push("error", s.error)
                            return False
                        if attempt == 2 or (e.status < 500 and e.status != 429):
                            if (why := no_credit(e.text)) or e.status == 402:
                                raise Fatal(why or no_credit("payment required"))
                            s.throttled = e.status == 429 or bool(_THROTTLED.search(e.text))
                            s.error = f"API error {e.status}: {e.text[:300]}"
                            s.push("error", s.error)
                            return False
                        s.push("info", f"the model server answered {e.status}; retrying in {2 ** attempt}s")
                    except httpx.TransportError as e:  # ReadTimeout mostly: nothing on the wire for `timeout` seconds
                        if attempt == 2:
                            s.server_down = True  # the session loop switches to the patience ladder
                            s.error = (f"{type(e).__name__}: the model server stopped answering"
                                       + (f" (no bytes for {timeout:.0f}s)" if isinstance(e, httpx.ReadTimeout) else "")
                                       + " — it may be busy, stuck, or not running")
                            s.push("error", s.error)
                            return False
                        s.push("info", f"the model server stopped answering ({type(e).__name__}); "
                                       f"retrying in {2 ** attempt}s")
                    time.sleep(2 ** attempt)
                    attempt += 1
                msg = reply["message"]
                finish = reply.get("finish_reason") or ""
                usage = reply.get("usage") if isinstance(reply.get("usage"), dict) else {}
                if usage.get("total_tokens"):
                    self._account(s, {"tokens": usage["total_tokens"]})
                if msg.get("reasoning_content"):
                    s.push("think", msg["reasoning_content"][:2000])
                if msg.get("content"):
                    s.push("text", msg["content"])
                calls = msg.get("tool_calls") or []
                messages.append({k: v for k, v in msg.items() if k in ("role", "content", "tool_calls")} | {"role": "assistant"})
                if not calls:
                    # A model that was cut off mid-thought (the server's own output limit) or that answered
                    # without touching a tool looks "done" — but it isn't: nudge it instead of ending the
                    # session (three such "sessions" used to trip the agent's three-strikes stop).
                    if nudges < 3 and finish == "length":
                        nudges += 1
                        s.push("info", "the reply was cut off at the model server's output limit (finish_reason=length) "
                                       "— raising its max tokens (mistral/mlx: --max-tokens) avoids this; asking it to "
                                       "continue")
                        messages.append({"role": "user", "content":
                                         "Your previous reply was cut off by the model server's output limit. Continue "
                                         "exactly where you stopped; keep messages short and call a decomp.wtf tool as "
                                         "soon as you can."})
                        continue
                    if nudges < 3 and not used_tool and (msg.get("content") or "").strip():
                        nudges += 1
                        messages.append({"role": "user", "content":
                                         "You haven't used a decomp.wtf tool yet. Call one now (claim_function, then "
                                         "compile_and_diff), or finish with release_function and notes."})
                        continue
                    return used_tool
                for c in calls:
                    name = c["function"]["name"]
                    try:
                        args = json.loads(c["function"].get("arguments") or "{}")
                    except ValueError:
                        args = {}
                    used_tool = True
                    s.push("tool", f"{name}({_args_brief(args)})")
                    result = tools.call(self.net, agent, s.slug, name, args)
                    messages.append({"role": "tool", "tool_call_id": c["id"], "content": result})
                if len(messages) > 80:  # keep the conversation small: summarize by restarting fresh
                    return True
        return used_tool


class _ModelServerError(Exception):
    """A non-2xx answer from an OpenAI-compatible endpoint, whole, so the retry loop can read the status."""

    def __init__(self, status: int, text: str):
        super().__init__(f"{status}: {text[:300]}")
        self.status = status
        self.text = text


def _api_timeout(base: str, options: dict) -> float:
    """Seconds of silence allowed on one streamed call. A local model can spend many minutes in
    prefill or a long answer (27B/262K models do); remote providers keep the 15-minute limit."""
    default = 3600.0 if is_local(base) else 900.0
    try:
        return max(30.0, float(options.get("timeout") or default))
    except (TypeError, ValueError):
        return default


def _completion(client: httpx.Client, url: str, headers: dict, body: dict) -> dict:
    """One chat completion, streamed so a slow local model keeps the call alive token by token.

    A non-streaming call has no bytes on the wire until the whole answer is done, so a local model that
    thinks for minutes (a long prompt, a long answer) ends in httpx.ReadTimeout and burns a session run.
    With streaming the read timeout only fires when the server truly goes quiet. Answers normalize to
    {"message", "finish_reason", "usage"}; a server that ignores stream=True and answers plain JSON is
    accepted as it is.
    """
    content: list[str] = []
    reasoning: list[str] = []
    calls: dict[int, dict] = {}
    finish = ""
    usage: dict = {}
    lines: list[str] = []
    with client.stream("POST", url, headers=headers,
                       json={**body, "stream": True, "stream_options": {"include_usage": True}}) as r:
        if r.status_code != 200:
            r.read()
            raise _ModelServerError(r.status_code, r.text)
        for line in r.iter_lines():
            lines.append(line)
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except ValueError:  # keep-alives and comments between events
                continue
            if isinstance(chunk.get("usage"), dict):
                usage = chunk["usage"]
            for ch in chunk.get("choices") or []:
                delta = ch.get("delta") or {}
                if delta.get("content"):
                    content.append(delta["content"])
                if delta.get("reasoning_content"):
                    reasoning.append(delta["reasoning_content"])
                for tc in delta.get("tool_calls") or []:
                    call = calls.setdefault(tc.get("index", 0), {"id": tc.get("id") or "",
                                                                 "type": tc.get("type") or "function",
                                                                 "function": {"name": "", "arguments": ""}})
                    if tc.get("id"):
                        call["id"] = tc["id"]
                    fn = tc.get("function") or {}
                    call["function"]["name"] += fn.get("name") or ""
                    call["function"]["arguments"] += fn.get("arguments") or ""
                if ch.get("finish_reason"):
                    finish = ch["finish_reason"]
            if finish:
                break  # the answer is complete; don't wait for a [DONE] a local server may never send
    if not any(line.startswith("data:") for line in lines):  # ignored stream=True: the whole reply arrived as JSON
        reply = json.loads("\n".join(lines) or "{}")
        choice = (reply.get("choices") or [{}])[0]
        return {"message": choice.get("message") or {}, "finish_reason": choice.get("finish_reason") or "",
                "usage": reply.get("usage") if isinstance(reply.get("usage"), dict) else {}}
    msg: dict = {"role": "assistant", "content": "".join(content) or None}
    if reasoning:
        msg["reasoning_content"] = "".join(reasoning)
    if calls:
        msg["tool_calls"] = [calls[i] for i in sorted(calls)]
    return {"message": msg, "finish_reason": finish, "usage": usage}


def _trim_history(messages: list[dict], keep_recent: int = 6, keep_chars: int = 400) -> list[dict]:
    """The conversation a model call actually carries: old tool outputs elided to their first lines.

    Tool results are the bulk of an agent's history (diffs are long), and only the newest one drives the
    next decision — without this, every turn re-sends every diff ever seen and cumulative billed tokens
    grow with turns². The instructions and the claim brief stay intact; the recent exchanges stay whole;
    nothing is lost for good (the app keeps the attempts, notes and scores)."""
    if len(messages) <= keep_recent + 2:
        return messages
    cut = len(messages) - keep_recent
    out: list[dict] = []
    for i, m in enumerate(messages):
        content = m.get("content")
        if i < cut and m.get("role") == "tool" and isinstance(content, str) and len(content) > keep_chars:
            out.append({**m, "content": content[:keep_chars]
                        + f"\n…({len(content) - keep_chars} chars elided to keep context small; the full text is "
                          f"in the app's history)"})
        else:
            out.append(m)
    return out


def _tokens(obj) -> int:
    """A cautious token estimate: code and assembly run about 3 characters a token."""
    return len(obj if isinstance(obj, str) else json.dumps(obj)) // 3 + 4


def _too_long(r) -> bool:
    """The server refused the request because it doesn't fit the model's context."""
    status = getattr(r, "status_code", None) or getattr(r, "status", 0)
    return status in (400, 413, 422, 500) and bool(re.search(
        r"context|too long|exceed|maximum.*tokens|n_ctx|prompt is too|reduce the length", r.text[:2000], re.I))


def fit(messages: list[dict], budget: int) -> int:
    """Shrink the conversation to `budget` tokens: older tool output goes first (a function's assembly and diffs
    from several steps ago), then older reasoning. The instructions, the task and the latest exchange stay whole.
    Returns the estimate after."""
    total = sum(_tokens(m) for m in messages)
    keep_from = max(2, len(messages) - 2)
    for kinds in (("tool",), ("assistant",)):
        for m in messages[2:keep_from]:
            if total <= budget:
                return total
            text = m.get("content")
            if m.get("role") in kinds and isinstance(text, str) and len(text) > 300:
                before = _tokens(m)
                m["content"] = text[:240] + "\n[... trimmed to save context: call the tool again if you need this]"
                total -= before - _tokens(m)
    return total


def context_window(client, base: str, options: dict) -> int:
    """The model's context in tokens: what the user set, else what a llama.cpp server reports (/props), else a
    guess (local servers often run small contexts)."""
    try:
        if int(options.get("context_tokens") or 0) >= 2048:
            return int(options["context_tokens"])
    except (TypeError, ValueError):
        pass
    if is_local(base):
        try:
            r = client.get(re.sub(r"/v1$", "", base) + "/props", timeout=5)
            n = (r.json().get("default_generation_settings") or {}).get("n_ctx") if r.status_code == 200 else None
            if isinstance(n, int) and n >= 2048:
                return n
        except (httpx.HTTPError, ValueError, AttributeError):
            pass
        return 16384
    return 128000


def api_tool_schemas(native: bool = False) -> list[dict]:
    """OpenAI-style tool definitions for the built-in agent, from the same tools CLI agents get."""
    s = lambda **props: {"type": "object", "properties": props, "required": [k for k, v in props.items() if v.pop("req", False)]}
    st = lambda desc, req=False: {"type": "string", "description": desc, "req": req}
    it = lambda desc: {"type": "integer", "description": desc}
    defs = {
        "project_info": ("Which game, compiler and progress.", s()),
        "set_mode": ("Choose a function's mode: decompile (body target), header (signature/class only; never "
                     "claimed), or skip. Matched functions cannot be hidden. Header/skip drops a live claim.",
                     s(function=st("exact function name", True), mode=st("decompile | header | skip", True),
                       note=st("why (stored for the next agent)"))),
        "set_signature": ("Edit one function's declaration without a body: class method (gated registry) or "
                          "free/namespace prototype. Use it for header-mode functions and wrong return/param "
                          "spellings; a wrong mangling fails the symbol check.",
                          s(function=st("exact function name", True), ret=st("return type, e.g. void", True),
                            params=st("comma-separated parameters (empty/void = none)"),
                            const=st('"true" for a const method'), static=st('"true" for a static method'),
                            virtual=st('"true" for a virtual method'), note=st("why"))),
        "claim_function": ("Claim the next function (or one by name/address). Returns assembly, data, best attempt, "
                           "notes and a draft. count > 1: a batch of small functions to judge together.",
                           s(function=st("optional name or address"), strategy=st("finish | easiest | closest | hardest | random"),
                             count=it("up to 6 small functions at once"))),
        "get_function": ("Show any function by name or address.", s(function=st("name or address", True))),
        "compile_and_diff": ("Compile C for the function, link it at its address and diff against the original. "
                             "Score 0 = matched. Several functions: names comma-separated, all definitions in one "
                             "source. Native programs: `flags` probes this one build with those compiler flags "
                             "(nothing is recorded) — use it to find the build that was shipped (e.g. -O0 vs -O2).",
                             s(function=st("function name, or several: a, b, c", True), source=st("C source", True),
                               flags=st("optional compiler flags to probe with (native)"))),
        "declare_opaque": ("Declare a project-global opaque third-party type (Boost, protobuf, OpenSSL, …): "
                           "a stub + alias rendered before every type block, so a class method may name it "
                           "without the real headers. Pass decl=\"\" to remove it. By-value stubs should "
                           "carry size/align/trivial (the ABI class); pointer/reference-only ones need none.",
                           s(name=st("project-global key, e.g. acme::thirdparty::yield_context", True),
                             decl=st("the stub/alias text; empty removes", True),
                             size=st("byte size for a by-value type"), align=st("alignment"),
                             trivial=st('"true" or "false" — trivially copyable/destructible'),
                             note=st("why this stub is right"))),
        "set_build_flags": ("Set the compiler flags compiles are judged with (native programs); with `function`, "
                            "they are saved on that function alone (probe first with compile_and_diff flags=…). "
                            "Use scope=\"file\" to pin the whole source file. Every matched function whose "
                            "flags change is recompiled; the change is rejected if any match breaks.",
                            s(flags=st("flags, e.g. -O2", True),
                              function=st("optional: attach to this function (default) or its file"),
                              scope=st('"function" (default) or "file"'))),
        "search_types": ("Type registry (native): find classes/structs/enums by name fragment, namespace, member, "
                         "kind, or the function that uses them — check it before hand-rolling a struct.",
                         s(query=st("name fragment (empty lists all)"), ns=st("namespace prefix, e.g. ACME::Aurora::Core"),
                           member=st("member name or type fragment"), kind=st("struct | class | union | enum"),
                           used_by=st("only types this function's source mentions"), limit=it("max rows"))),
        "get_type": ("One registry type: layout with offsets, where it came from, and the matched functions a "
                     "change would re-verify.",
                     s(name=st("type name, bare or qualified", True))),
        "declare_type": ("Add a type to the shared registry (stripped binaries / pruned classes). Gated: every "
                         "matched function affected must still match before it is kept.",
                         s(name=st("qualified name, e.g. ACME::Aurora::Core::Node", True), kind=st("struct | class | union | enum"),
                           size=it("size in bytes if known"), note=st("where you saw it: alloc site, vtable, this-pointer"),
                           session=st("lock_registry token: stage now, verify once on unlock"))),
        "edit_type": ("Edit a registry type (gated). set_member / set_method / remove_method / set_static / rename_member / remove_member / set_size / move / hide / unhide / merge.",
                      s(action=st("set_member | set_method | remove_method | set_static | rename_member | remove_member | set_size | move | hide | unhide | merge", True),
                        name=st("type name", True), member=st("member/method/static name (or 0x offset)"),
                        mtype=st("member or static type, or return type for set_method"),
                        at=st("byte offset for set_member, e.g. 8 or 0x8"), count=it("array count"),
                        params=st("set_method: comma-separated parameter list (empty = none); remove_method: narrow to one overload"),
                        static=st('set_method: "true" for a static member function'),
                        new_name=st("rename target"), other=st("merge partner"), scope=st("move: namespace, e.g. ACME::Aurora::Core"),
                        size=it("set_size bytes"), note=st("why"),
                        session=st("lock_registry token: stage now, verify once on unlock"))),
        "lock_registry": ("Take the registry for a batch of edits: stage with declare_type/edit_type(session=…), "
                          "then unlock_registry verifies the whole batch in one pass. Other edits wait while held; "
                          "the lock expires by itself if you go quiet.",
                          s(wait=it("seconds to wait for another session to end (0 = don't wait)"))),
        "unlock_registry": ("End a registry session: commit (verify the batch once) or abort (discard it). "
                            "A rejected batch stays staged so you can fix it and commit again.",
                            s(session=st("the token lock_registry returned", True), action=st("commit | abort"))),
        "release_function": ("Hand a function off after ~20 compiles, or with a filed report documenting a blocker; "
                             "notes are required and the best attempt is kept. Earlier handoffs are refused.",
                             s(function=st("function", True), notes=st("what you tried, what is left", True))),
        "get_context": ("The header this function's next compile will receive, rendered exactly (entries + legacy "
                        "visible text + fresh projection — the same pipeline compile_and_diff runs).",
                        s(function=st("the function whose unit you want (required on per-file projects)", True))),
        "edit_context": ("Replace `old` (exactly once) with `new` in the shared header, or append when old is empty.",
                         s(old=st("text to replace, or empty", True), new=st("replacement", True),
                           message=st("why", True))),
        "declare": ("Declare a UNIT-SCOPE fact the unit compiles against (free function, global/static, typedef, "
                    "freestanding include, note): kind = prototype | static | alias | include | note. Not for class "
                    "members (use add_method). Gated: a breaking entry is withdrawn.",
                    s(body=st("the declaration text", True), kind=st("prototype | static | alias | include | note"),
                      function=st("function whose unit it belongs to", True))),
        "undeclare": ("Remove a declaration entry by declared name or entry id (gated: restored at its old position "
                      "when it breaks a match).",
                      s(name=st("declared name"), entry=it("entry id"), function=st("function whose unit it belongs to", True))),
        "edit_decls": ("Edit several declaration entries atomically — the repair path for a unit wedged by more than "
                       "one entry (removing either alone still breaks compiles). remove: comma-separated ids (#25) "
                       "or names; add: JSON array of {kind, body}. One gate over the resulting header.",
                       s(remove=st("ids or names, comma-separated"), add=st('JSON: [{"kind":"prototype","body":"int f(void);"}]'),
                         function=st("function whose unit it belongs to", True))),
        "list_decls": ("List the live declaration entries behind the unit's generated header.",
                       s(function=st("function whose unit it belongs to", True))),
        "promote_legacy": ("Move declaration text out of the frozen legacy header into an entry (the only way to "
                           "edit frozen text); old must occur once; new (default same) becomes the entry. Gated.",
                           s(old=st("exact stored-header text", True), new=st("replacement declaration text"),
                             kind=st("raw | prototype | static | alias"), function=st("function whose unit it belongs to", True))),
        "promote_type": ("Free a type definition from the frozen legacy header so the registry owns it: the stored "
                         "definition is removed (gated) and the projection renders the registry's version — after "
                         "which edit_type/add_method changes reach the compile.",
                         s(name=st("type name, e.g. ACME::...::String", True),
                           function=st("function whose unit holds the definition", True), message=st("why"))),
        "add_method": ("Add/replace a member function on a class/struct (the right way to declare Ns::Class::method; "
                       "a file-scope prototype of a member is refused). promote_type first if the class is still "
                       "defined in the frozen seed. Gated.",
                       s(name=st("qualified type name", True), method=st("method name", True),
                         ret=st("return type (default void)"), params=st("comma-separated parameters (empty = none)"),
                         static=st('"true" for a static member function'), note=st("why"))),
        "report": ("File a stack wall on the project todo list: kind=bug (a tool misbehaves / an error you cannot "
                   "work around) or need (a missing capability). Identical titles merge.",
                   s(kind=st("bug | need", True), title=st("one line", True),
                     detail=st("what you tried and what you expected"), function=st("the function it blocked, if any"))),
        "read_data": ("Hex dump of the original's data at an address, a function name or a named global/static.", s(what=st("address or symbol", True),
                                                                                    length=it("bytes, up to 512"))),
        "ida": ("Ask the project's IDA database directly (read-only, cached): xrefs (to/from, with kinds), "
                "disasm (a function name gives its whole body in one call; an address gives a window), decompile "
                "(Hex-Rays), types (IDA's type library), globals, strings, segments.",
                s(action=st("xrefs | disasm | decompile | types | globals | strings | segments", True),
                  query=st("name, address or filter"), count=it("max items"))),
        "list_functions": ("List functions by status — or search them by name fragment / address.",
                           s(status=st("open | working | matched | library | all"), limit=it("max rows"),
                             query=st("optional name fragment or 0x address"))),
        "add_note": ("Leave a note for other agents.", s(text=st("note", True), function=st("function"))),
        "search_notes": ("Search notes.", s(query=st("text", True))),
        "guide": ("Decompilation know-how; no topic lists topics.", s(topic=st("topic"))),
    }
    names = set(tools.tool_names(native))
    return [{"type": "function", "function": {"name": n, "description": d, "parameters": p}}
            for n, (d, p) in defs.items() if n in names]


def _terminate(proc: subprocess.Popen) -> None:
    try:
        if WIN:
            # the agent with everything it started (node starts opencode.exe, ...): terminate() would only end the
            # first process and leave the rest working, and spending, in the background
            res = subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, timeout=30)
            if res.returncode != 0 and proc.poll() is None:
                proc.terminate()
        else:
            os.killpg(proc.pid, 15)
    except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
        pass
