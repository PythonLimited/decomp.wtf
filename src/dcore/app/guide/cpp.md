# Decompiling C++

The symbol is the mangled name; it encodes the class, the parameter types and const-ness, so the
definition must have exactly that signature or objdiff won't find it.
- CodeWarrior (GameCube, Wii, DS): `update__7CPlayerFf` = `CPlayer::update(float)`;
  `__ct__7CPlayerFv` constructor, `__dt__7CPlayerFv` destructor, `__vt__7CPlayer` vtable,
  `__sinit_file_cpp` static initialisers.
- Itanium (Switch Clang, many 3DS/PS2/PS3 compilers): `_ZN7CPlayer6updateEf`; `C1`/`C2` and `D0`/`D1`/`D2`
  are the constructor/destructor variants.
- MSVC (PC, Xbox): `?update@CPlayer@@QAEXM@Z`.
The brief shows the demangled name when there is one.

Structure
- `this` is the first argument (r3 on PPC, r0 on ARM, x0 on AArch64, ecx with MSVC thiscall).
- Destructors take a hidden flag (CodeWarrior: in r4) and call `operator delete` when it's > 0.
- Virtual calls load the vtable pointer, then the function at a fixed offset. CodeWarrior places the
  vtable pointer after the members of the class that first declares virtual functions, so it's often
  not at offset 0; Itanium and MSVC put it at offset 0.
- Getters, setters and small helpers in class bodies are inline: the target shows direct field access.
- Templates (containers, math types) are instantiated as weak functions, often in many files.
- `new`/`delete`: `__nw__FUl` / `__dl__FPv` (CodeWarrior), `_Znwm` / `_ZdlPv` (Itanium).

Matching tips
- Get the class layout from offsets used across many methods (`search_code` the class name first:
  it's probably already declared).
- Optimization flags are saved per function by default: probe with
  `compile_and_diff(flags="…")`, then adopt with `set_build_flags(flags, function=…)`.
  Use `scope="file"` only when the whole translation unit really shared them.
- A wrapper whose plain source ends in a tail `jmp`, while the target keeps
  `sub rsp,8; call; add rsp,8; ret`, usually came from a TU built with
  `-fno-optimize-sibling-calls`. Probe that flag before changing the source.
- A default constructor listed by the debug info may have been implicit in the original. If declaring
  it makes the class non-aggregate (or leaves a call to an undefined symbol), remove it with
  `edit_type(action="remove_method", name=<class>, member=<class>)`; the class becomes an aggregate
  again and brace initialization is available.
- A named local returned by value can place its temporary deeper on the stack than a direct
  `return T{...}`. If only `s` (stack-offset) markers differ, try both forms before changing types.
- Member initialisation order in constructors follows declaration order in the class, not the
  initialiser list order.
- Inlined base-class constructors show up as stores of the base vtable before the derived one.
- Exceptions and RTTI are usually off in games; if the target has EH tables, the project says so.
