import sys

import pytest

from dcore.core import jobs, worker


def _command(code: str) -> str:
    return f'{sys.executable} -c "{code}"'


def test_run_solver_feeds_json_and_reads_source(tmp_path):
    job = {"function": "f", "context": "int f(void);\n",
           "include_files": {"inc/a.h": "int a;\n"}}
    source = worker.run_solver(
        _command("import sys,json; j=json.load(sys.stdin); print('int f(void) { return %d; }' % len(j['context']))"),
        job)
    assert source == "int f(void) { return 13; }"


def test_run_solver_rejects_empty_output_and_failure():
    with pytest.raises(worker.WorkerError, match="no source"):
        worker.run_solver(_command("pass"), {})
    with pytest.raises(worker.WorkerError, match="exited 3"):
        worker.run_solver(_command("raise SystemExit(3)"), {})


def test_run_solver_times_out():
    with pytest.raises(worker.WorkerError, match="timed out"):
        worker.run_solver(_command("import time; time.sleep(5)"), {}, timeout=0.1)


def test_remote_worker_claims_and_submits(monkeypatch):
    calls = []
    job = {"project": "game", "function": "f", "unit": "u",
           "context": "int f(void);\n", "include_files": {}}

    def post(url, token, path, payload, timeout=60.0):
        calls.append((path, payload))
        if path == "/api/worker/claim":
            return {"job": job}
        return {"accepted": True, "matched": True, "score": 0}

    monkeypatch.setattr(worker, "_post", post)
    monkeypatch.setattr(worker, "run_solver", lambda command, job, timeout=300: "int f(void) { return 1; }")
    stats = worker.run_remote("http://coordinator", "dn_test", command="solver", count=1)
    assert stats == {"attempted": 1, "matched": 1, "rejected": 0, "no_jobs": False}
    assert calls[0][0] == "/api/worker/claim"
    assert calls[1] == ("/api/worker/submit",
                        {"project": "game", "function": "f", "source": "int f(void) { return 1; }"})


def test_worker_claims_runs_and_submits(monkeypatch):
    calls = []

    class Net:
        def claim_row(self, agent, project=None, function=None):
            calls.append(("claim", project, function))

        def _function(self, function, project=None):
            return {"id": 1, "name": function}

    job = {"project": "game", "function": "f", "unit": "u",
           "context": "int f(void);\n", "include_files": {},
           "source": "int f(void) { return 1; }"}
    monkeypatch.setattr(jobs, "next_job", lambda net, agent, project=None, function=None: job)
    monkeypatch.setattr(jobs, "submit", lambda net, agent, project, function, source: (
        calls.append(("submit", project, function, source)) or
        {"accepted": True, "matched": True, "score": 0}))
    monkeypatch.setattr(worker, "release_claim", lambda *a, **k: None)
    agent = type("A", (), {"id": 7, "name": "worker"})()
    stats = worker.run_worker(Net(), agent, command=_command("print('int f(void) { return 1; }')"),
                              project="game", count=1)
    assert stats == {"attempted": 1, "matched": 1, "rejected": 0, "no_jobs": False}
    assert calls[0] == ("claim", "game", "f")
    assert calls[1][0:2] == ("submit", "game")
