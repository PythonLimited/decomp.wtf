# dcore

**Byte-exact decompilation for shipped binaries.**

`dcore` reconstructs C/C++ functions from a linked binary. It combines analysis
from IDA (or another backend) with a pinned compiler and a judge that compares
resolved destinations, not symbol spellings.

It is the standalone core extracted from the discontinued **decomp.wtf**
application: the decompilation loop, type/header registry, compiler/judge, and
platform packs. The old app's catalogs, rooms, self-update, and launcher are not
part of this project. See [Legacy project](#legacy-project).

---

## Why dcore

- **Byte-exact, not approximate.** A match means the rebuilt object is identical
  after relocations are resolved.
- **The header is generated, not hand-maintained.** Types live in one registry;
  each function gets a header scoped to its own callees.
- **The judge understands real references.** Code/data addresses, imports,
  section offsets, local branches, thunks, and self-calls are canonicalised.
- **Packs, not a monolith.** Architecture and platform rules are separate, so
  the core loop does not know what an ELF or an x86 is.
- **Built for agents.** The app exposes an MCP endpoint; an AI edits the header
  and function body through tools, then calls the same compile/judge path.

---

## How it works

```text
import ─► analyze ─► plan ─► claim ─► get_context ─► compile_and_diff ─► judge
                                                         │
                                                         └─ header projection
```

1. **Import** the binary and create a project.
2. **Analyze** it with IDA/Ghidra: functions, types, names, xrefs, pseudocode.
3. **Plan** groups functions into units and assigns compiler settings.
4. **Claim** one function so only one agent works on it.
5. **Get context**: the function's callee environment, types, and generated header.
6. **Compile and judge** the submitted function against the target bytes.
7. **Export** a reconstructable source tree when the project is ready.

### The judge

The target is the linked image; the candidate is an object from the project's
pinned toolchain. The judge compares:

- code/data destinations, not their names;
- imports, thunks, and IAT/PLT aliases;
- data addends and x86 PC-relative bias;
- function-local branches, normalised as `@local:<offset>`;
- recursive self-calls.

An unresolved project name fails with an explicit alias path:
`name_function(name, address)` or `name_data(name, address)`.

`strict_rejudge` re-runs every matched function against the current header and
judge without changing its status.

### Types and headers

One registry is shared by every function:

- class/struct/union kind, bases, empty bases, bitfields, alignment;
- template primaries and explicit specialisations;
- methods merged from observed class-qualified signatures;
- forward declarations and dependency ordering;
- demand-driven providers (`<atomic>`, `<vector>`, `<cstddef>`, `<cstdarg>`, …);
- opaque by-value fallback at the real size when a type is missing
  (stripped binaries, boost internals, incomplete PDB data);
- GCC-safe MSVC spellings (`__int64` → `long long`);
- a function-scoped compile header that declares only what that function needs.

---

## Requirements

| Need | Notes |
|---|---|
| Python 3.12+ | managed with `uv` |
| `uv` | dependency and command runner |
| Docker | pinned GCC/MSVC compiler images |
| Analysis backend | **optional**: licensed IDA Pro, or Ghidra (Apache-2.0; adapter planned). Core matching works without one. |

Currently tested on **macOS only**. The compiler containers actively emulate the
target architecture (for example `linux/amd64` on Apple silicon), so other host
platforms are unvalidated and may be slow.

---

## Analysis backends

A backend is enrichment: it supplies names, types, xrefs, strings and decompiler
text. The matcher itself works from the bytes, the reconstructed relocations and
the pinned compiler, so it does not need one.

| Backend | Status | You need | What it adds |
|---|---|---|---|
| **IDA Pro** | ready | a licensed IDA Pro with IDAPython; `.i64` reuse is supported | best type recovery and Hex-Rays pseudocode; names/xrefs/strings |
| **Ghidra** | planned — high priority | Ghidra (Apache-2.0) with a supported JDK; PyGhidra or a headless analyzer | a free, scriptable decompiler and headless analysis; fewer type-recovery features than IDA |
| **None** | always available | nothing | byte-exact matching; no database names, xrefs or pseudocode seeds |

Licensing boundaries:

- This repository is MIT. The backends are **separate programs under their own
  licenses**; none of their code, SDK headers or databases are bundled here.
- IDA Pro is commercial. Users supply their own license; IDA Free has
  commercial-use restrictions. Check the EULA before automating or hosting it.
- Ghidra is Apache-2.0. The adapter talks to it out-of-process (headless JSON or
  PyGhidra); no Ghidra code is copied into this tree.
- Decompiled output still belongs to the game's rights holder. The app must not
  distribute game code or databases.

See `src/dcore/backends/` for the shared `Analysis` contract; IDA is implemented,
Ghidra is the next backend.

### Setting up IDA Pro

1. Install a licensed **IDA Pro with IDAPython and idalib** (IDA 9.x; check your
   license for headless/automation use). IDA Free is not licensed for commercial
   use.
2. Install the bridge once, so `dcore` can spawn it:

   ```bash
   uvx ida-hcli mcp install
   ```

   This provides `ida-mcp`; having `ida-mcp` on `PATH` works too.
3. If you use a custom server command, point dcore at it:

   ```bash
   export DECOMPNET_IDA_MCP="/path/to/ida-mcp stdio --agent=decomp-wtf"
   ```

4. Start dcore and import your binary. A matching `.i64` is reused when present;
   sweeps are cached by the binary's SHA-256, so IDA is paid for once per file.
5. If the database is open in the IDA desktop app, registry edits still save, but
   the IDA write-through queues until you close it. The app reports the queued
   count.

### Setting up Ghidra (planned — high priority)

The Ghidra adapter is **not wired yet**; this is the prerequisite setup, not an
enabled backend. Until it lands, dcore uses IDA or runs without a backend.

1. Install **Ghidra** (Apache-2.0) and the JDK its release notes require
   (recent Ghidra releases use JDK 21).
2. Use one of the two integration paths the adapter will support:
   - Ghidra's headless analyzer, `support/analyzeHeadless`, with the adapter's
     JSON script;
   - **PyGhidra**, which ships with recent Ghidra, for in-process Python.
3. Keep the Ghidra install path available; the adapter will need it to find
   `analyzeHeadless` or the PyGhidra runtime. No dcore setting for this exists
   until the adapter lands.

### No backend

Nothing to install. The matcher still compiles each function with the pinned
compiler and compares bytes and relocations; you lose database names, xrefs and
pseudocode seeds.


---

## Install

```bash
git clone https://github.com/PythonLimited/decomp.wtf.git
cd decomp.wtf
git switch dcore
uv sync --extra dev
```

---

## Quick start

### 1. Start the app

```bash
uv run dcore
```

This starts the local server and web UI. The session URL is printed in the
terminal; open it, then import a binary and let the app analyze it.

### 2. Connect an agent

```bash
uv run dcore mcp --name my-agent
```

The MCP endpoint exposes the project tools: claim, context, registry edits,
compile/judge, aliases, and export.

For a CLI agent:

```bash
uv run dcore connect codex
```

### 3. Work one function

Typical agent flow:

```text
claim_function
get_context
  edit the header via the registry, if needed
compile_and_diff
  read the diff, iterate
```

A submission is exactly one function. Types and globals belong in the header;
the AI does not paste a type block into the source.

### 4. Optional: donated compute

```bash
uv run dcore worker --project <slug> \
  --solver "python examples/worker_solver.py" --count 10
```

A solver reads job JSON on stdin and prints a replacement function body. The
worker contract is documented in the local `docs/WORKER.md`; the worker is
optional and only handles near-miss jobs.

---

## Examples

- [`examples/agent-loop/`](examples/agent-loop/) — a hidden static getter, with
  the exact claim, visibility edit, flags, and source the agent uses.
- [`examples/mock-engine/`](examples/mock-engine/) — a compilable synthetic
  engine for the names used in tests and docs.
- [`examples/worker_solver.py`](examples/worker_solver.py) — the optional
  donated-compute solver template.

---

## Core concepts

| Concept | Meaning |
|---|---|
| **Project** | one binary plus its analysis, compiler card, and registry |
| **Target** | `arch × platform`, e.g. `win × x86_64`, `linux × aarch64` |
| **Pack** | an arch or platform rule set; packs compose freely |
| **Unit** | a source file grouping functions with the same compiler/flags |
| **Claim** | a lease on one function for one agent |
| **Registry** | the single source of truth for types, entries, and aliases |
| **Header** | a generated, function-scoped projection of the registry |
| **Match** | judge verdict with zero byte/reference differences |

---

## Packs

| Area | Status |
|---|---|
| `x86_64` | ready |
| `x86`, `aarch64` | declared; operand/relocation work remaining |
| ELF / DWARF | ready (GCC/Clang triples) |
| PE / COFF | ready (Rich header, PDB path, pure-Python `.pdata`/imports/TLS/load-config seeds) |
| Mach-O | universal slices, dSYM-aware DWARF |
| Android | ELF skin, NDK toolchains, bionic markers |

Pinned compilers validated on generated headers:

- GNU `gcc`/`g++` **9.1.0**
- MSVC **19.00** (VS2015 U3) via `dcore-msvc-hangover:2015u3`
- `dcore-msvc-wine` is provided for amd64; on arm64 it runs under emulation

---

## Repository layout

```text
src/dcore/
  core/          loop, registry, header projection, judge, compiler, worker
  backends/      analysis adapters (IDA ready; Ghidra planned)
  targets/       arch and platform packs
  app/           server, web UI, MCP tools, CLI

tests/           unit and end-to-end tests
docker/          pinned GCC/MSVC images
examples/        agent-loop walkthrough, mock engine, worker solver
docs/            local design notes (untracked)
```

---

## Testing

```bash
uv run pytest -q
# 233 passed, 1 skipped
```

The mock engine is a compilable fixture for the synthetic names used in docs
and tests:

```bash
cd examples/mock-engine
make run
# match=1 allocated=1 heap=0
```

Validation snapshots:

- a 548k-function x86-64 PE target: **77/77 matched functions** pass strict rejudge;
- a 378k-function Linux ELF target: key headers parse with GCC 9.1.0.

---

## Status and limitations

- `_refresh`, `export`, and `jobs` still use the unit-level renderer in places;
  compile, context, and gate use the function-scoped renderer.
- Windows declarations use the ambient SDK when a header names Windows types; a
  pinned ABI/SDK provider is not finished.
- `x86` and `aarch64` operand rules, PDB parsing, and some object readers remain.
- The donated-compute worker is optional and currently serves near-miss jobs
  only.

---

## Legacy project

**decomp.wtf is discontinued and unmaintained.** `dcore` is the maintained
decompilation core only; the original application is not supported.

- Site: <https://decomp.wtf>
- Original repository: <https://github.com/PythonLimited/decomp.wtf>

---

## Contributing

Read [AGENTS.md](AGENTS.md) before changing the repository. It documents the
clean-room rules: no ROMs or proprietary binaries, no real project names or
identifiers, no copied source, synthetic fixtures only, and the required tests.

---

## License

MIT. See [LICENSE](LICENSE).
