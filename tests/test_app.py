"""The local app: GUI API security, demo import, live feed, agent output parsing, the built-in API agent."""

import json
import os
import shutil
import sys
import time

import httpx
import pytest
from starlette.testclient import TestClient

from dcore.app import agents
from dcore.core.engine import Engine
from dcore.app.server import build

PORT, SECRET = 6499, "s3cret-for-tests"


@pytest.fixture(scope="module")
def app(tmp_path_factory):
    home = tmp_path_factory.mktemp("home")
    (home / ".decomp").mkdir()
    net = Engine(home / ".decomp" / "decomp.db", home)
    mcp, manager, security = build(net, home / ".decomp", PORT, SECRET)
    app = mcp.streamable_http_app(transport_security=security, host="127.0.0.1")
    client = TestClient(app, base_url=f"http://127.0.0.1:{PORT}")
    client.cookies.set("decomp_live", SECRET)
    return client, net, manager


def test_gui_needs_the_secret_and_the_right_host(app):
    client, _, _ = app
    anon = TestClient(client.app, base_url=f"http://127.0.0.1:{PORT}")
    assert anon.get("/api/state").status_code == 401
    assert anon.get("/").status_code == 401
    r = anon.get(f"/?k={SECRET}", follow_redirects=False)
    assert r.status_code == 303 and "decomp_live" in r.headers["set-cookie"] and "samesite=strict" in r.headers["set-cookie"].lower()
    evil = TestClient(client.app, base_url="http://evil.example:6499")
    evil.cookies.set("decomp_live", SECRET)
    assert evil.get("/api/state").status_code == 403
    # writes need the custom header too (a cross-site form can't send it)
    assert client.post("/api/settings", json={"per_session": 3}).status_code == 403
    assert client.post("/api/settings", json={"per_session": 3}, headers={"X-Decomp": "1"}).status_code == 200
    # these tests script the agents themselves: no autopilot after the import
    assert client.post("/api/settings", json={"autopilot": False}, headers={"X-Decomp": "1"}).json()["autopilot"] is False


def test_settings_never_echo_the_api_key(app):
    client, _, _ = app
    out = client.post("/api/settings", json={"api": {"provider": "deepseek", "api_key": "sk-abcdef123456"}},
                      headers={"X-Decomp": "1"}).json()
    assert "sk-abcdef" not in json.dumps(out) and out["api"]["has_key"]
    assert "sk-abcdef" not in json.dumps(client.get("/api/state").json())


def test_parse_agent_output():
    claude = json.dumps({"type": "assistant", "message": {"content": [
        {"type": "text", "text": "Matched it."},
        {"type": "tool_use", "name": "mcp__decomp__compile_and_diff", "input": {"function": "f", "source": "a\nb"}}]}})
    assert agents.parse_line("claude", claude) == [("text", "Matched it."), ("tool", "compile_and_diff(f, 2 lines of C)")]
    codex = json.dumps({"type": "item.started", "item": {"type": "mcp_tool_call", "server": "decomp", "tool": "claim_function",
                                                        "arguments": {"strategy": "easiest"}}})
    assert agents.parse_line("codex", codex) == [("tool", "claim_function(easiest)")]
    opencode = json.dumps({"type": "text", "part": {"text": "done"}})
    assert agents.parse_line("opencode", opencode) == [("text", "done")]
    assert agents.parse_line("claude", "not json at all") == [("info", "not json at all")]


def test_opencode_js_sandbox_calls_show_the_decomp_tool_inside():
    """opencode v2 reaches MCP servers through its JS sandbox: the event is its built-in `execute`
    tool carrying a script — the feed shows the decomp call that script makes, not the script."""
    script = (
        'const r1 = await tools["decomp"].claim_function({function: "ACME::Aurora::Core::Score::value()"});\n'
        "const r2 = await tools.decomp.search_types({query: `TraceLog`, limit: 5});\n"
        "const src = `\nint f() {\n    return 1;\n}\n`;\n"
        'const r3 = await tools.decomp.compile_and_diff({function: "f", source: src});\n'
        "console.log(r1, r2, r3);\n")
    line = json.dumps({"type": "tool_use", "part": {"tool": "execute", "state": {"input": {"code": script}}}})
    assert agents.parse_line("opencode", line) == [
        ("tool", "claim_function(function: ACME::Aurora::Core::Score::value())"),
        ("tool", "search_types(query: TraceLog, limit: 5)"),
        ("tool", "compile_and_diff(function: f, source: 3 lines)"),
    ]
    # an execute that touches nothing named decomp still shows as a short script line
    other = json.dumps({"type": "tool_use", "part": {"tool": "execute",
                                                     "input": {"code": "const files = await ls('.');\n"}}})
    assert agents.parse_line("opencode", other) == [("tool", "execute(const files = await ls('.');)")]


def test_the_session_fence_denies_the_app_home_and_the_game_files():
    """Agents get their answers from the tools; the OS fence denies the filesystem those answers
    would otherwise come from (the app's home, the repo, the game's exe/pdb/i64, credentials)."""
    profile = agents.session_fence()
    assert profile.startswith("(version 1)") and "(allow default)" in profile
    assert "file-read* file-write*" in profile
    for path in ("decomp-home", "Desktop", "Downloads", ".ssh"):
        assert path in profile


def test_opencode_is_not_given_the_removed_dir_flag(tmp_path, monkeypatch):
    """opencode v2 dropped `run --dir`, so every session died as "Unrecognized flag: --dir". The project
    directory is the process cwd anyway (agents._run_cli spawns with cwd=workdir); the command must not
    name it. On macOS the CLI also runs under the session fence, so every built-in read tool inherits it."""
    manager = object.__new__(agents.Manager)
    manager.mcp_url = "http://127.0.0.1:1/mcp"
    manager.prompt = lambda s: "p"
    monkeypatch.setattr(agents, "_which", lambda cmd: f"/usr/local/bin/{cmd}")
    # a real (non-Zen) model, so the permissions stay the plain "deny" this test is about
    s = agents.Session("oc-1", "opencode", "L", "slug", "oc", {"model": "anthropic/claude-sonnet-4"})
    cmd, _, prompt = manager._command(s, "tok", tmp_path)
    head = 0
    from pathlib import Path

    if agents.sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").exists():
        assert cmd[0] == "/usr/bin/sandbox-exec" and cmd[1] == "-p"
        assert "decomp-home" in cmd[2] and "Downloads" in cmd[2]
        head = 3
    assert cmd[head] == "/usr/local/bin/opencode" and cmd[head + 1] == "run" and "--format" in cmd
    assert "--standalone" in cmd  # a private server per run: the shared daemon's sessions outlived
    # every app-side stop and auto-resumed with it, which kept "killed" agents working for hours
    assert "--dir" not in cmd and str(tmp_path) not in cmd
    assert prompt == "p" and "p" not in cmd  # the prompt goes in on stdin, not as an argument
    cfg = json.loads((tmp_path / "opencode.json").read_text(encoding="utf-8"))
    assert cfg["mcp"]["servers"]["decomp"]["codemode"] is False  # direct tools, not the JS sandbox
    assert {"action": "shell", "resource": "*", "effect": "deny"} in cfg["permissions"]
    assert "permission" not in cfg  # the v1 spelling is gone


def test_old_tool_outputs_are_elided_for_the_model():
    """Token control: every turn re-sends the conversation, so old diffs collapse to their first lines —
    the newest stays whole, the instructions and the brief never shrink, and nothing is unpaired."""
    messages = [{"role": "system", "content": "s"}, {"role": "user", "content": "brief"}]
    for i in range(12):
        messages.append({"role": "assistant", "content": "", "tool_calls":
                         [{"id": f"c{i}", "function": {"name": "compile_and_diff", "arguments": "{}"}}]})
        messages.append({"role": "tool", "tool_call_id": f"c{i}", "content": f"diff {i} " + "B" * 5000})
    trimmed = agents._trim_history(messages)
    assert trimmed[0]["content"] == "s" and trimmed[1]["content"] == "brief"  # instructions + brief intact
    assert trimmed[3]["content"].startswith("diff 0 ") and "elided" in trimmed[3]["content"]
    assert len(trimmed[3]["content"]) < 600
    assert trimmed[-1]["content"] == messages[-1]["content"]  # the newest result stays whole
    assert len(trimmed) == len(messages)  # tool_call pairing preserved
    assert agents._trim_history(messages[:6]) == messages[:6]  # a young conversation isn't touched


def test_api_agent_can_probe_and_adopt_build_flags():
    defs = {d["function"]["name"]: d["function"] for d in agents.api_tool_schemas()}
    assert "set_build_flags" in defs  # the built-in API agent gets the same tools as the CLI agents
    params = defs["compile_and_diff"]["parameters"]
    assert "flags" in params["properties"] and set(params["required"]) == {"function", "source"}


class _SchemasNet:
    """Just enough net for the built-in agent loop: a mock project, and no tools called in these scripts."""

    def fork_slug(self, *a):
        return None

    def native_slug(self, *a):
        return None

    def overview(self, slug):
        return {"kind": "rom", "platform": "n64", "platform_name": "Nintendo 64", "title": "Mock",
                "compiler": {"toolchain": "gcc-2.7.2-kmc"}}

    def instructions(self, slug):
        return ""


def _api_session(tmp_path, options=None):
    manager = agents.Manager(_SchemasNet(), tmp_path, "http://127.0.0.1:9/mcp")
    s = agents.Session("api-t", "api", "Test", "slug", "api-test",
                       {"base_url": "http://mock/v1", "model": "m", "api_key": "k"} | (options or {}))
    return manager, s


def _mock_client(monkeypatch, handler):
    real = httpx.Client
    monkeypatch.setattr(agents.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr(agents.time, "sleep", lambda *_: None)


def test_a_flaky_model_server_is_retried_in_place(tmp_path, monkeypatch):
    """The local MLX server answered 500 several times: that must not burn a whole session (three of those
    used to stop the agent entirely)."""
    manager, s = _api_session(tmp_path)
    replies = iter([None, None, {"content": "thinking"}, {"content": "more"}, {"content": "more"},
                    {"content": "done"}])
    posts = []

    def handler(request):
        posts.append(json.loads(request.content))
        item = next(replies)
        if item is None:
            return httpx.Response(500, text="boom")
        return httpx.Response(200, json={"choices": [
            {"message": {"role": "assistant", "content": item["content"]}, "finish_reason": "stop"}]})

    _mock_client(monkeypatch, handler)
    assert manager._run_api(s, None) is False  # it never used a tool: reported honestly, not as a crash
    assert len([f for f in s.feed if "retrying" in f["text"]]) == 2  # both 500s retried in place
    assert not any(f["type"] == "error" for f in s.feed)
    assert len(posts) == 6  # 3 attempts consumed by the two 500s, then the nudged content turns


def test_a_truncated_reply_is_continued_not_abandoned(tmp_path, monkeypatch):
    """finish_reason=length means the model server cut the answer: say so and ask it to continue instead of
    treating the session as finished (three of those used to trip the agent's three-strikes stop)."""
    manager, s = _api_session(tmp_path, {"max_tokens": 4096})
    replies = iter([
        {"content": "The layout starts like {", "finish": "length"},
        {"content": "carrying on", "finish": "stop"},
        {"content": "still carrying on", "finish": "stop"},
        {"content": "done", "finish": "stop"},
    ])
    posts = []

    def handler(request):
        posts.append(json.loads(request.content))
        item = next(replies)
        return httpx.Response(200, json={"choices": [
            {"message": {"role": "assistant", "content": item["content"]}, "finish_reason": item["finish"]}]})

    _mock_client(monkeypatch, handler)
    assert manager._run_api(s, None) is False
    assert posts[0]["max_tokens"] == 4096  # an explicit cap is passed through when the option is set
    assert "cut off" in posts[1]["messages"][-1]["content"]  # the continuation nudge
    assert "decomp.wtf tool" in posts[2]["messages"][-1]["content"]  # a second nudge kind: use the tools
    assert any("output limit" in f["text"] for f in s.feed)


def test_a_streamed_answer_is_rebuilt_from_sse_chunks(monkeypatch):
    """Local servers stream: content and tool-call arguments arrive in pieces, and a half-written argument
    must rebuild into one reply (a non-streaming client can't even see the pieces)."""
    seen = []

    def handler(request):
        seen.append(json.loads(request.content))
        events = [
            {"choices": [{"delta": {"role": "assistant", "content": "Mat"}, "finish_reason": None}]},
            {"choices": [{"delta": {"content": "ched."}, "finish_reason": None}]},
            {"choices": [{"delta": {"tool_calls": [
                {"index": 0, "id": "call_1", "type": "function",
                 "function": {"name": "claim_function", "arguments": '{"func'}}]}, "finish_reason": None}]},
            {"choices": [{"delta": {"tool_calls": [
                {"index": 0, "function": {"arguments": 'tion": "f"}'}}]}, "finish_reason": "tool_calls"}],
             "usage": {"total_tokens": 42}},
        ]
        return httpx.Response(200, headers={"content-type": "text/event-stream; charset=utf-8"},
                              text="".join(f"data: {json.dumps(e)}\n\n" for e in events) + "data: [DONE]\n\n")

    _mock_client(monkeypatch, handler)
    with agents.httpx.Client() as client:
        reply = agents._completion(client, "http://mock/v1/chat/completions", {}, {"model": "m", "messages": []})
    assert seen[0]["stream"] is True
    assert reply["message"]["content"] == "Matched."
    (call,) = reply["message"]["tool_calls"]
    assert call["function"]["name"] == "claim_function"
    assert json.loads(call["function"]["arguments"]) == {"function": "f"}
    assert reply["finish_reason"] == "tool_calls" and reply["usage"]["total_tokens"] == 42


def test_a_stream_that_stops_at_finish_reason_is_not_awaited():
    """Some local servers end the answer with finish_reason and keep the HTTP stream open (no
    data: [DONE]). The reader must stop there, not wait out the hour-long local read timeout."""
    class Response:
        status_code = 200
        def __enter__(self): return self
        def __exit__(self, *exc): return False
        def read(self): pass
        def iter_lines(self):
            yield 'data: {"choices":[{"delta":{"content":"hi"},"finish_reason":"stop"}]}'
            raise AssertionError("kept reading after finish_reason")

    class Client:
        def stream(self, *a, **k): return Response()

    reply = agents._completion(Client(), "http://mock/v1/chat/completions", {}, {})
    assert reply["message"]["content"] == "hi" and reply["finish_reason"] == "stop"


def test_local_models_get_an_hour_between_stream_chunks():
    """A 27B/262K local model can spend many minutes in prefill; remote providers keep 15 minutes."""
    assert agents._api_timeout("http://127.0.0.1:8080/v1", {}) == 3600
    assert agents._api_timeout("https://api.example.com/v1", {}) == 900
    assert agents._api_timeout("http://127.0.0.1:8080/v1", {"timeout": 120}) == 120


def test_a_local_model_that_goes_quiet_is_retried_not_failed(tmp_path, monkeypatch):
    """An httpx.ReadTimeout used to reach the runner as a failed run (three of those stop the agent). A
    server that stalls on one call gets another instead — that is the whole point of the longer wait."""
    manager, s = _api_session(tmp_path)
    calls = []

    def handler(request):
        calls.append(json.loads(request.content))
        if len(calls) == 1:
            raise httpx.ReadTimeout("timed out")
        return httpx.Response(200, json={"choices": [
            {"message": {"role": "assistant", "content": "hello"}, "finish_reason": "stop"}]})

    _mock_client(monkeypatch, handler)
    assert manager._run_api(s, None) is False  # content only, it never used a tool: reported honestly
    assert any("stopped answering" in f["text"] for f in s.feed)
    assert not any(f["type"] == "error" for f in s.feed)  # the stall cost a retry, not the session
    assert len(calls) > 1


def test_an_agent_nobody_signed_in_to_stops_and_says_so(tmp_path, monkeypatch):
    """Claude Code without a sign-in exits at once: say that (not "exited with code 1") and don't keep retrying."""
    manager = agents.Manager(None, tmp_path, "http://127.0.0.1:9/mcp")
    code = "print('Not logged in \\u00b7 Please run /login'); raise SystemExit(1)"
    monkeypatch.setattr(manager, "_command", lambda s, token, workdir: ([sys.executable, "-c", code], dict(os.environ), ""))
    s = agents.Session("claude-1", "claude", "Claude Code #1", "game", "claude-1", {})
    assert manager._run_cli(s, "token", tmp_path) is False
    assert s.signed_out and "isn't signed in" in s.error and "/login" in s.error


def test_cli_agents_are_spawned_with_pwd_matching_the_workdir(tmp_path, monkeypatch):
    """Popen(cwd=workdir) doesn't touch the inherited PWD — and opencode v2 resolves its project directory
    from PWD, which sent its sessions into the app's own repo, without their config or the decomp MCP tools."""
    manager = agents.Manager(None, tmp_path, "http://127.0.0.1:9/mcp")
    code = ("import json, os; print(json.dumps({'type': 'text', 'part': "
            "{'text': os.environ.get('PWD') + ' | ' + os.getcwd()}}))")
    monkeypatch.setattr(manager, "_command",
                        lambda s, token, workdir: ([sys.executable, "-c", code], dict(os.environ), ""))
    s = agents.Session("oc-1", "opencode", "opencode #1", "slug", "oc", {})
    assert manager._run_cli(s, "token", tmp_path) is False  # nothing tool-shaped: reported as a quiet run
    assert any(f["type"] == "text" and f["text"] == f"{tmp_path} | {tmp_path}" for f in s.feed)


def test_an_agent_out_of_credit_stops_and_says_so(tmp_path, monkeypatch):
    """DeepSeek's "Insufficient Balance" (here through opencode): stop at once and say what to do. "Too many
    requests" is the provider's limit of requests at once: not a failure, the session waits and tries again."""
    manager = agents.Manager(None, tmp_path, "http://127.0.0.1:9/mcp")
    s = agents.Session("opencode-1", "opencode", "opencode #1", "game", "opencode-1", {})

    def says(text: str) -> None:
        code = f"print({text!r}); raise SystemExit(1)"
        monkeypatch.setattr(manager, "_command", lambda s, token, workdir: ([sys.executable, "-c", code], dict(os.environ), ""))

    says("AI_APICallError: Insufficient Balance (request_id: 3e759c3b)")
    with pytest.raises(agents.Fatal, match="out of credit .*Insufficient Balance.*top it up"):
        manager._run_cli(s, "token", tmp_path)
    says("AI_APICallError: Too many requests. Your current concurrency is 5, which exceeds your concurrency limit of 5")
    assert manager._run_cli(s, "token", tmp_path) is False and s.throttled


def test_agent_spend_is_read_from_their_output():
    claude = agents.parse_line("claude", json.dumps({"type": "result", "total_cost_usd": 0.42, "num_turns": 9}))
    assert ("usage", json.dumps({"usd": 0.42})) in claude and any(k == "info" for k, _ in claude)
    codex = agents.parse_line("codex", json.dumps({"type": "turn.completed", "usage": {"input_tokens": 900, "output_tokens": 100}}))
    assert ("usage", json.dumps({"tokens": 1000})) in codex
    opencode = agents.parse_line("opencode", json.dumps({"type": "step_finish", "part": {"cost": 0.01}}))
    assert ("usage", json.dumps({"usd": 0.01})) in opencode


def test_an_older_bridge_never_stops_a_newer_app(tmp_path, monkeypatch):
    """An agent set up with an older install's `decomp mcp` must use the newer app that's running, not replace it."""
    from dcore.app import cli

    monkeypatch.setattr(cli, "_running_version", lambda port: "99.0.0")
    state = tmp_path / "server.json"
    state.write_text(json.dumps({"port": 1234, "secret": "s"}))
    assert cli.replace_older(state, log=lambda *_: None) == {"port": 1234, "secret": "s"}
    assert cli._version_key("0.10.0") > cli._version_key("0.9.4")


def test_a_job_always_ends_and_says_why(tmp_path):
    """Whatever goes wrong in an import, the job ends with words the user can act on and the log has the whole
    story: before, an error of a kind nobody caught left the GUI on "Analysing…" forever."""
    import subprocess

    from dcore.app.server import Jobs

    jobs = Jobs(tmp_path / "logs" / "decomp.log")

    def wait(jid):
        for _ in range(200):
            if jobs.jobs[jid]["state"] != "running":
                return jobs.jobs[jid]
            time.sleep(0.01)
        raise AssertionError("the job never ended")

    def bug(log):
        log("reading the ROM")
        return {}["missing"]

    def slow(log):
        raise subprocess.TimeoutExpired(["/usr/bin/systemd-run", "--user", "--", "/x/luvdis", "disasm"], 1800)

    def failed(log):
        raise subprocess.CalledProcessError(2, ["ninja"], stderr=b"ld: undefined symbol foo")

    job = wait(jobs.start("import", bug))
    assert job["state"] == "error" and "KeyError" in job["error"] and "report" in job["error"]
    assert "Traceback" in job["trace"]
    assert "luvdis took longer than 30 minutes" in wait(jobs.start("import", slow))["error"]
    assert wait(jobs.start("build", failed))["error"] == "ninja failed (2): ld: undefined symbol foo"
    logged = (tmp_path / "logs" / "decomp.log").read_text()
    assert "reading the ROM" in logged and "KeyError" in logged and "Traceback" in logged


def test_the_log_can_be_read_from_the_gui(app):
    client, _, _ = app
    res = client.get("/api/log")
    assert res.status_code == 200 and res.headers["content-type"].startswith("text/plain")
    anon = TestClient(client.app, base_url=f"http://127.0.0.1:{PORT}")
    assert anon.get("/api/log").status_code == 401


def test_a_project_that_cant_be_read_is_listed_with_the_reason(app, monkeypatch):
    """One odd project used to empty the whole sidebar (or quietly vanish from it)."""
    client, net, _ = app
    with net.store.tx() as db:
        db.execute("INSERT INTO projects(slug,name,description,arch,big_endian,root,config) VALUES(?,?,?,?,?,?,?)",
                   ("odd-game", "Odd Game", "", "mips", 1, "/nowhere", "{}"))
    real = net.overview

    def overview(slug, *a, **k):
        if slug == "odd-game":
            raise TypeError("'NoneType' object is not subscriptable")
        return real(slug, *a, **k)

    monkeypatch.setattr(net, "overview", overview)
    listed = {p["slug"]: p for p in client.get("/api/projects").json()}
    assert "TypeError" in listed["odd-game"]["broken"] and listed["odd-game"]["title"] == "Odd Game"
    assert any("broken" not in p for p in listed.values()) or len(listed) == 1
    assert client.get("/api/state").status_code == 200
    with net.store.tx() as db:
        db.execute("DELETE FROM projects WHERE slug='odd-game'")


def test_fit_keeps_the_task_and_the_latest_exchange():
    msgs = [{"role": "system", "content": "rules " * 100}, {"role": "user", "content": "task " * 100}]
    for k in range(6):
        msgs += [{"role": "assistant", "content": f"thinking {k} " * 50},
                 {"role": "tool", "tool_call_id": str(k), "content": f"assembly {k} " * 400}]
    agents.fit(msgs, 3000)
    assert msgs[0]["content"] == "rules " * 100 and msgs[1]["content"] == "task " * 100
    assert msgs[-1]["content"] == "assembly 5 " * 400  # the latest result, whole
    assert "trimmed" in msgs[3]["content"]


def test_the_mcp_surface_registers_every_tool_exactly_once():
    """A decorator left behind by a dropped wrapper stacked onto its successor: the server then exposed
    duplicate tools (read_data twice, the `work` prompt as four tools). Registration must be one name each."""
    import asyncio

    from dcore.app import tools as tools_mod
    from dcore.core.engine import Engine

    net = Engine(tmp_path := __import__("pathlib").Path("/tmp") / "dcore-mcp-surface.db", __import__("pathlib").Path("/tmp") / "dcore-mcp-surface")
    mcp = tools_mod.build_mcp(net, lambda ctx: (None, ""))
    listed = asyncio.run(mcp.list_tools())
    names = [t.name for t in listed]
    assert len(names) == len(set(names)), f"duplicate tools: {sorted(n for n in names if names.count(n) > 1)}"
    # the library *ignores* a second registration of the same name, so count decorators, not names:
    # one @mcp.tool per wrapper and exactly one prompt, or a stacked decorator has come back
    from pathlib import Path as _Path

    src = (_Path(__file__).resolve().parent.parent / "src" / "dcore" / "app" / "tools.py").read_text()
    assert src.count("@mcp.tool(") == len(names), "a wrapper carries more than one @mcp.tool decorator"
    assert src.count("@mcp.prompt(") == 1
    assert names.count("read_data") == 1 and names.count("guide") == 1
    assert "work" not in names  # work is a prompt, not a tool
    assert {"claim_function", "compile_and_diff", "search_types", "edit_context"} <= set(names)


def test_the_ui_only_calls_routes_the_server_has():
    """The static UI is one hand-written file; a route it calls that no longer exists is a dead button.
    Collect every /api/... path from app.js and index.html and require each in server.py."""
    import re
    from pathlib import Path as _Path

    root = _Path(__file__).resolve().parent.parent / "src" / "dcore" / "app"
    ui = (root / "static" / "app.js").read_text(encoding="utf-8") + (root / "static" / "index.html").read_text(encoding="utf-8")
    server = (root / "server.py").read_text(encoding="utf-8")
    calls = set(re.findall(r"/(api/[a-z0-9/_-]+)", ui))
    routes = set(re.findall(r"/(api/[a-z0-9/_-]+)", server))
    assert calls, "no endpoints found in the UI at all"
    assert not (calls - routes), f"the UI calls routes the server doesn't have: {sorted(calls - routes)}"


def test_no_console_language_survives_in_the_ui():
    """This build plans shipped programs (ELF/PE/Mach-O). The console world was dropped from the code —
    the static files must not still offer it (a dead panel or a dead word is the same bug)."""
    from pathlib import Path as _Path

    root = _Path(__file__).resolve().parent.parent / "src" / "dcore" / "app" / "static"
    text = (root / "app.js").read_text(encoding="utf-8") + "\n" + (root / "index.html").read_text(encoding="utf-8")
    for word in ("CodeWarrior", "Nintendo", "GameCube", "PlayStation", "Game Boy", "mwcc", "objdiff", "m2c", "splat",
                 "decomp.dev", "dtk-template", "ds-decomp", "splat64", "/api/fork", "/api/collab",
                 "/api/catalog", "/api/update", "/api/toolchain", "/api/service"):
        assert word not in text, f"the UI still mentions {word!r}"
    assert " ROM" not in text and text.count("ROM") == 0, "the UI still says ROM"
