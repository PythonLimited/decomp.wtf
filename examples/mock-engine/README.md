# Mock engine

This is a small, self-contained stand-in for the identifiers that used to appear in
the repository. It exists so examples, tests and docs are not naming fictional types
without any definition behind them.

## Naming map

| Synthetic | Role |
|---|---|
| `ACME` | company namespace |
| `Aurora` | engine namespace |
| `Obsidian` | framework namespace |
| `tracekit` / `TraceLog` | diagnostics |
| `ORION` / `orion-s` | sample binary/project |
| `Retail` | sample build configuration |
| `Dm*` | sample allocator entry points |

## Build

```bash
cd examples/mock-engine
make run
```

Expected output:

```text
match=1 allocated=1 heap=0
```

## Files

- `include/acme/aurora/core/memory.hpp` — `Memory`, `OSMemory`, `DebugMemoryTag`.
- `include/acme/obsidian/base/string.hpp` — `Allocatable`, `String`,
  `DynamicArray`, `SmallPointer`.
- `src/string.cpp` — `String::ExtractMatch` and basic string operations.
- `src/memory.cpp` — allocator/memory-tag stubs.
- `src/demo.cpp` — a runnable call through both namespaces.

The sample is intentionally small; it is a fixture, not a full engine.
