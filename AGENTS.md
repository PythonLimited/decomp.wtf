# AGENTS.md

Rules for anyone — human or AI — changing this repository.

## What this repository is

`dcore` is a clean-room decompilation core. It must remain publishable under
the MIT license. Do not turn it into a distribution of someone else's game,
engine, SDK, or source tree.

## Hard prohibitions

Never add, commit, link, or upload:

- ROMs, game images, ISOs, disc images, executables, firmware, PAK/WAD/XEX/NSP/
  PKG files, or any other proprietary binary or asset;
- proprietary source code, leaked source, reconstructed source from a real
  project, SDK headers, PDBs, debug databases, engine headers, or copied
  decompilation output;
- real company, game, engine, framework, product, character, or project names
  in code, tests, docs, fixtures, comments, commit messages, branch names, or
  file names;
- identifiers, strings, paths, type names, mangled symbols, project slugs, or
  log excerpts taken from a real binary;
- keys, tokens, passwords, cookies, session URLs, or private configuration;
- generated analysis files (`.i64`, `.idb`, `analysis*.json`), registries from a
  real project, screenshots or logs that expose real names, or large binary
  fixtures.

If a fixture needs a binary, generate a minimal synthetic one in the test.
If a symbol needs a name, use the synthetic vocabulary below.

## Clean-room rules

- Use only generic, public behavior and your own implementation. Do not copy
  code, comments, tables, or test data from a proprietary source tree.
- Do not paste a real function body “as a reference”, even temporarily.
- Do not add comments such as “from <real project>” or link to leaked material.
- Do not include third-party code unless it is a declared dependency with a
  compatible license and is used through its public API.
- Contributions are accepted under the repository's MIT license.

## Synthetic vocabulary

Use these names consistently in examples, tests, and docs:

| Synthetic | Role |
|---|---|
| `ACME` | company namespace |
| `Aurora` | engine namespace |
| `Obsidian` | framework namespace |
| `tracekit` / `TraceLog` | diagnostics |
| `ORION` / `orion-s` | sample binary/project |
| `Retail` | sample build configuration |
| `Dm*` | sample allocator entry points |

`examples/mock-engine/` is the compilable fixture for this vocabulary. Extend
it instead of inventing a new fictional API.

## Repository hygiene

- `docs/` is intentionally untracked and ignored; keep working notes local.
- Do not commit `.qwen/`, `.venv/`, caches, build output, Docker staging, or
  generated artifacts.
- Keep `LICENSE` as MIT and keep the `pyproject.toml` license metadata in sync.
- Do not rewrite published history or force-push `main`/tags without the
  repository owner's explicit approval.
- Do not commit unrelated local changes.

## Before committing

1. Run the suite:

   ```bash
   uv run pytest -q
   ```

2. Run the mock fixture:

   ```bash
   make -C examples/mock-engine run
   ```

3. Scan the tree for forbidden names using your local, untracked list (keep
   the list itself outside the repository):

   ```bash
   git grep -I -n -i -f "${DCORE_FORBIDDEN_NAMES:-$HOME/.config/dcore/forbidden-names.txt}"
   ```

   A base64 fixture must be decoded and checked too; regenerating it with
   synthetic names is preferred over replacing characters in place.

4. Check `git status` and stage only the files that belong to the change.

## Scope

The legacy application is discontinued and is not maintained here. This
repository contains the decompilation core only; do not reintroduce its
catalogs, rooms, launcher, self-update, or game-specific assets.
