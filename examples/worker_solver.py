#!/usr/bin/env python3
"""Example solver for `dcore worker`.

The worker invokes this with the job JSON on stdin and reads the replacement function
source from stdout. This file supports two modes:

  * SOLVER_SOURCE_FILE=/tmp/known.cpp  -> print that file (useful for a controlled test)
  * OPENAI_API_KEY=...                 -> ask an OpenAI-compatible chat model

Optional:
  SOLVER_BASE_URL   default https://api.openai.com/v1
  SOLVER_MODEL      default gpt-4o-mini

The model is told to return exactly one C/C++ function definition. It is a starting
point; a real decompilation solver should also compile/judge locally and iterate.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request


def strip_fences(text: str) -> str:
    text = text.strip()
    m = re.search(r"```(?:cpp|c\+\+|c|cc)?\s*(.*?)```", text, re.S | re.I)
    return (m.group(1) if m else text).strip()


def ask_model(job: dict) -> str:
    base = os.environ.get("SOLVER_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    key = os.environ.get("OPENAI_API_KEY", "")
    model = os.environ.get("SOLVER_MODEL", "gpt-4o-mini")
    if not key:
        raise SystemExit("set OPENAI_API_KEY, or SOLVER_SOURCE_FILE for a file-only test")
    prompt = f"""You are reconstructing one function from a decompiled binary.
Return ONLY the complete replacement function definition, no prose and no code fences.

Function: {job.get('function')}
Current best source (score {job.get('best_score')} / {job.get('max_score')}):
{job.get('source')}

Header context:
{(job.get('context') or '')[:24000]}

Rules:
- Keep the same signature and ABI.
- Do not add types, globals, helpers, includes, or namespace wrappers.
- Preserve the original control flow and memory layout.
"""
    body = json.dumps({"model": model, "temperature": 0,
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request(base + "/chat/completions", data=body, method="POST",
                                 headers={"Authorization": f"Bearer {key}",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"model HTTP {e.code}: {e.read()[:400].decode(errors='replace')}") from None
    try:
        return strip_fences(data["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError):
        raise SystemExit("model returned no message content") from None


def main() -> int:
    job = json.load(sys.stdin)
    path = os.environ.get("SOLVER_SOURCE_FILE")
    source = open(path, encoding="utf-8").read().strip() if path else ask_model(job)
    if not source:
        raise SystemExit("solver produced no source")
    print(source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
