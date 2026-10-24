# Resolver canaries

Two tiny synthetic programs with the exact first-slice toolchains:

| Target | Toolchain | Output |
|---|---|---|
| GCC | GCC 9.1.0, ELF x86_64, `-std=c++14 -O2 -g -fPIC` | `build/gcc91/acme-canary` |
| MSVC | VS2015 U3 / 19.00.24210, PE x86_64, `/O2 /EHsc /MD /Zi` | `build/vs2015/acme-canary.obj` |
| MSVC PE | same compiler, freestanding `/NODEFAULTLIB` link | `build/vs2015/acme-canary-min.exe` + `.pdb` |

The MSVC image carries headers and `cl`, but not the VC `lib/` tree. The full
C++14 canary therefore compiles to an object for codegen validation. The
freestanding PE canary is linked without the CRT so there is still a real PE +
PDB for environment resolution and judge preflight. A fully linked C++ canary
needs a complete VS2015 toolset with its libraries mounted or built into the
image.

The source is known, so these can validate the environment resolver, the
canonical prelude, the per-function header, and the judge before a real binary.

Expected identity:

- GCC DWARF producer:
  `GNU C++14 9.1.0 -mtune=generic -march=x86-64 -g -O2 -std=c++14 -fPIC ...`
  → `gcc-9.1.0-x86_64-linux-gnu`.
- MSVC PE/PDB banner: `Microsoft (R) C/C++ Optimizing Compiler Version
  19.00.24210 for x64` → `msvc-19.00.24210-x86_64-pc-windows-msvc`.

## Build

```bash
tests/canary/build.sh          # both
tests/canary/build.sh gcc      # GCC only
tests/canary/build.sh msvc     # MSVC only
```

The GCC image is `gcc:9.1.0` on `linux/amd64`. On Apple silicon the MSVC script
uses `dcore-msvc-hangover:2015u3` on `linux/arm64`; on x86-64 it uses
`dcore-msvc-wine:2015u3` on `linux/amd64`. Override with `GCC_IMAGE`,
`GCC_PLATFORM`, `MSVC_IMAGE`, `MSVC_PLATFORM`.

The generated binaries are ignored; do not commit them.

## What the source covers

`src/canary.cpp` contains noinline, reachable functions for:

- leaf integer and float/double arithmetic;
- a struct with members and methods;
- a bitfield struct;
- single inheritance, a virtual call, and RTTI;
- a global read/write;
- `std::vector` and `std::string` use;
- an exception throw/catch;
- an explicit template instantiation;
- a variadic function.

The next step after building is to import each canary through the IDA provider,
assert that `resolve_analysis()` picks the matching descriptor, and compile the
canary functions against the generated prelude.

## Vertical slice

```bash
tests/canary/build.sh gcc
uv run python tests/canary/slice.py
```

The slice:

1. reads the canary DWARF types/functions and the exact `DW_AT_producer`;
2. resolves and pins the GCC 9.1.0 environment;
3. converts the analysis into model facts;
4. renders `build/gcc91/context.h` and `build/gcc91/layout_probes.h`;
5. compiles the prelude + layout probes with GCC 9.1.0;
6. compiles three known function bodies and compares them with the target via
   the existing judge.

Expected tail:

```text
layout probe compile: ok
_ZN4ACME6Aurora3addEii: MATCH score=0
_ZNK4ACME6Aurora6Widget3getEv: MATCH score=0
_ZN4ACME6Aurora11flags_valueERKNS0_5FlagsE: MATCH score=0
_ZN4ACME6Aurora12call_virtualERKNS0_11VirtualBaseE: MATCH score=0
```

The GCC canary is built with `-fno-ipa-sra -fno-ipa-cp` (otherwise GCC can
clone a `noinline` method into `get.isra.0` and the source-named symbol the slice
wants to match disappears) and `-fno-devirtualize
-fno-devirtualize-speculatively` (otherwise the sole `Derived` call lets GCC
speculate a direct call into `call_virtual`, so a standalone candidate cannot
match). These flags are part of the pinned environment, so the candidate compile
uses them too. Expanding the flag set until a function matches is exactly what
`probe_environment` will formalize later.

## VS2015 slice

```bash
tests/canary/build.sh msvc
uv run python tests/canary/slice_msvc.py
```

The MSVC image has no VC link libraries, so this canary is a freestanding PE
(`/NODEFAULTLIB`) with exported functions. Exports provide authoritative RVAs;
the PDB provides types and code sizes. The linked PDB's public-address map was
not reliable for this tiny image, so the export table is the target address
source.

Expected tail:

```text
layout probe compile: ok
canary_add: MATCH score=0
?canary_widget@@YAHH@Z: MATCH score=0
?canary_flags@@YAIAEBUFlags@@@Z: MATCH score=0
?get@Widget@@QEBAHXZ: MATCH score=0
?set@Widget@@QEAAXH@Z: MATCH score=0
```

The slice resolves `msvc-19.00.24210-x86_64-pc-windows-msvc`, compiles
`/O2 /GS- /GR- /EHs-c-` objects with the pinned Hangover image, and judges
against the exported function bytes.
