# Agent-loop example: a hidden static getter

This example matches:

```asm
lea rax, [rip + time_offset]
mov rax, [rax]
ret
```

The target does **not** load the global directly. It takes the address of a
hidden static and then reads it through that address. A plain
`return Clock::time_offset;` will produce `mov rax, [rip + ...]` instead.

The agent needs four tool calls:

1. `claim_function`
2. `get_context`
3. `edit_type` — mark the static hidden
4. `set_build_flags` — adopt the codegen flags
5. `compile_and_diff`

## 1. Claim and read context

```text
claim_function("Clock::getTimeOffset")
get_context()
```

The header contains:

```cpp
static time_t time_offset;  /* defined elsewhere */
```

If the symbol is hidden in the original build, mark it:

```text
edit_type(
  action="set_static",
  name="ACME::Aurora::Core::Clock",
  member="time_offset",
  mtype="time_t",
  visibility="hidden"
)
```

The rendered header becomes:

```cpp
static __attribute__((visibility("hidden"))) time_t time_offset;
```

## 2. Adopt the per-function flags

```text
set_build_flags(
  "-O0 -fPIC -fvisibility=hidden -fomit-frame-pointer -march=x86-64",
  function="ACME::Aurora::Core::Clock::getTimeOffset"
)
```

`-O0` matters here: at `-O1`/`-O2` GCC folds the address read into a direct load.

## 3. Submit the source

```cpp
time_t ACME::Aurora::Core::Clock::getTimeOffset()
{
    return *reinterpret_cast<volatile time_t *>(&ACME::Aurora::Core::Clock::time_offset);
}
```

```text
compile_and_diff(
  function="ACME::Aurora::Core::Clock::getTimeOffset",
  source=<the function above>
)
```

Expected:

```text
✅ MATCH! ... byte-identical to the target (3 instructions).
```

## Why this works

- The static member is hidden, so GCC can resolve it without a GOT load.
- The volatile address read forces `lea` + `mov` instead of a folded direct load.
- The per-function flags preserve the original unoptimised code shape.

If your probe reports `mov rax, [rip + ...]` instead, check the visibility edit
first, then the flags. If it reports an extra `mov`, check that the source uses
the volatile address read rather than a plain member read.

This is an agent-loop example only; the real match is recorded by
`compile_and_diff`.
