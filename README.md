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
| IDA Pro | for the default IDA backend; `.i64` reuse is supported |
| Optional | Ghidra adapter (contract exists, implementation pending) |

Currently tested on **macOS only**. The compiler containers actively emulate the
target architecture (for example `linux/amd64` on Apple silicon), so other host
platforms are unvalidated and may be slow.

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
  backends/      analysis adapters (IDA, Ghidra contract)
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
