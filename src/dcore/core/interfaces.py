"""Generated headers: what a function compiles against.

Per source file the analysis produces a `context.h` — declarations of everything that file's
functions call into, so one function can be recompiled on its own (no linking). C is plain
prototypes. For C++ units the block is `extern "C"`: C-linkage callees get their plain name,
C++-linkage callees whose class layouts aren't reconstructed yet are declared by their
*mangled* name (inside `extern "C"` exactly once), with the demangled spelling in a comment.
The file's own functions are listed as comments only — real prototypes there would fight the
definition the agent writes. `edit_context` grows these headers, regression-tested.
"""

from __future__ import annotations

import re
from pathlib import Path

_CALLING = re.compile(r"\b__(?:fastcall|cdecl|stdcall|thiscall|pascal|usercall|noreturn|spoils"
                      r"(?:\s*<[^>]*>)?)\s*")
_TYPES = {"__int64": "long long", "__int32": "int", "__int16": "short", "__int8": "char",
          "_QWORD": "unsigned long long", "_DWORD": "unsigned int", "_WORD": "unsigned short",
          "_BYTE": "unsigned char", "_BOOL8": "bool", "_BOOL4": "int", "_BOOL2": "short",
          "_BOOL1": "bool", "_UNKNOWN": "long"}
_TYPEDEFS = ("typedef unsigned char uint8_t;\ntypedef unsigned short uint16_t;\ntypedef unsigned int uint32_t;\n"
             "typedef unsigned long long uint64_t;\ntypedef signed char int8_t;\ntypedef signed short int16_t;\n"
             "typedef signed int int32_t;\ntypedef signed long long int64_t;")


def sanitize(text: str) -> str:
    """IDA-flavored signature text -> plain C/C++ a gcc/clang speaks."""
    text = _CALLING.sub("", text or "")
    for old, new in _TYPES.items():
        text = re.sub(rf"\b{re.escape(old)}\b", new, text)
    return " ".join(text.split())


def signature_parts(signature: str) -> tuple[str, str] | None:
    """('int', 'int *score, int delta') for an IDA signature, None when it can't be parsed."""
    sig = sanitize(signature)
    if not sig or "(" not in sig or ")" not in sig:
        return None
    ret, rest = sig.split("(", 1)
    params = rest.rsplit(")", 1)[0]
    return (ret.strip() or "void", params)


def _hidden_this(sig: str) -> str:
    """IDA invents `Class *__hidden this` for a free function; it is not a parameter."""
    sig = re.sub(r"(?:[A-Za-z_]\w*(?:::\w+)*\s*[*&]+\s*)?__hidden\s+this", "", sig or "")
    return re.sub(r",\s*,", ",", sig).strip(", ")


def prototype(name: str, signature: str, *, cpp: bool = False) -> str:
    """`int __fastcall(int *score, int delta)` + name -> `int name(int *score, int delta);`"""
    signature = _hidden_this(signature)
    parts = signature_parts(signature)
    if parts is None:
        return f"long {name}();  /* IDA had no signature: fix this declaration if the call doesn't match */"
    ret, params = parts
    if cpp:
        # IDA spells the implicit object argument `this`; C++ reserves it, so a header carrying the
        # prototype verbatim is invalid before the function's first line is even parsed.
        params = re.sub(r"\bthis\b", "self", params)
    return f"{ret} {name}({params});"


_TYPENAME = re.compile(r"^(?:const\s+)?(?:unsigned\s+|signed\s+|long\s+|short\s+)*[A-Za-z_]\w*(?:::\w+)*"
                       r"(?:\s*[*&]+)?(?:\[\d+\])?$")
_TEMPLATE = re.compile(r"<(?=[^<=])")  # a real template argument; operator<</operator<=> never match
_STD_INCLUDES = {"vector": "vector", "list": "list", "forward_list": "forward_list", "deque": "deque",
                 "map": "map", "multimap": "map", "set": "set", "multiset": "set",
                 "unordered_map": "unordered_map", "unordered_set": "unordered_set",
                 "string": "string", "wstring": "string", "basic_string": "string",
                 "pair": "utility", "tuple": "tuple", "array": "array",
                 "unique_ptr": "memory", "shared_ptr": "memory", "weak_ptr": "memory", "allocator": "memory",
                 "optional": "optional", "variant": "variant", "function": "functional",
                 "atomic": "atomic", "mutex": "mutex", "condition_variable": "condition_variable",
                 "thread": "thread", "chrono": "chrono", "future": "future",
                 "stringstream": "sstream", "ostringstream": "sstream", "istringstream": "sstream",
                 "wstringstream": "sstream", "queue": "queue", "stack": "stack",
                 "priority_queue": "queue", "bitset": "bitset", "complex": "complex"}


def std_includes(text: str) -> list[str]:
    """The `#include <…>` lines a block of declarations needs for the std types it spells."""
    heads = set()
    for m in re.finditer(r"\bstd::(\w+)", text or ""):
        head = _STD_INCLUDES.get(m.group(1))
        if head:
            heads.add(head)
    for bare in ("ostringstream", "istringstream", "stringstream", "wstringstream"):
        if re.search(rf"\b{bare}\b", text or ""):
            heads.add("sstream")
    return [f"#include <{h}>" for h in sorted(heads)]


_STD_FORWARDS = {
    "vector": "template <class T, class A> class vector;",
    "list": "template <class T, class A> class list;",
    "deque": "template <class T, class A> class deque;",
    "map": "template <class K, class V, class C, class A> class map;",
    "set": "template <class K, class C, class A> class set;",
    "unique_ptr": "template <class T, class D> class unique_ptr;",
    "shared_ptr": "template <class T> class shared_ptr;",
}


def std_forwards(text: str) -> list[str]:
    """Forward declarations for std templates the text uses before any declaration.

    A legacy header may declare its own minimal `std::vector` after a pointer use
    (`extern std::vector<...> *p;`). The parser needs the name before line one; a forward
    declaration is harmless when the real definition follows, and when a toolchain header
    is included instead it is a redeclaration of the same template."""
    out = []
    for name, decl in _STD_FORWARDS.items():
        needle = f"std::{name}"
        first = (text or "").find(needle)
        if first < 0:
            continue
        before = text[:first]
        if re.search(rf"\b(?:class|struct)\s+{re.escape(name)}\b", before):
            continue
        out.append(f"namespace std {{ {decl} }}")
    return out


def system_includes(text: str, language: str, analysis: dict) -> list[str]:
    """System headers the target profile owns, for the platform types the declarations use.

    Same generator for ELF/Mach-O/PE and C/C++; only the target's headers differ. The generated
    layouts for these names are skipped, so the include is the only correct spelling.
    """
    fmt = _target_format(analysis)
    text = text or ""
    if fmt == "pe":
        heads = []
        if re.search(r"\b(?:sockaddr\w*|timeval|fd_set|WSADATA|SOCKET|addrinfo|hostent)\b", text):
            heads.append("winsock2.h")  # must precede windows.h
        # Only the declarations that actually name the platform need the SDK.  Blindly adding
        # windows.h made a pure C++ class header fail under gcc/Mingw and hid the fact that the
        # generated block is self-contained.
        windows = re.search(
            r"\b(?:HANDLE|HWND|HINSTANCE|HMODULE|DWORD|WORD|BYTE|BOOL|BOOLEAN|LPVOID|LPCVOID|"
            r"LPSTR|LPCSTR|LPWSTR|LPCWSTR|UINT|ULONG|LONG|SIZE_T|HRESULT|GUID|LARGE_INTEGER|"
            r"FILETIME|SYSTEMTIME|OVERLAPPED|SECURITY_ATTRIBUTES|CRITICAL_SECTION|"
            r"CreateFile\w*|ReadFile|WriteFile|CloseHandle|GetLastError|VirtualAlloc|"
            r"LoadLibrary\w*|GetProcAddress|MessageBox\w*|RegOpenKey\w*)\b", text)
        if windows:
            heads.append("windows.h")
        return [f"#include <{h}>" for h in heads]
    heads = set()
    if re.search(r"\bpthread_\w+", text):
        heads.add("pthread.h")
    if re.search(r"\b(?:timeval|timespec)\b", text):
        heads.add("sys/time.h")
    if re.search(r"\btm\b", text):
        heads.add("time.h")
    if re.search(r"\b(?:sockaddr\w*|addrinfo|hostent|iovec|msghdr|cmsghdr)\b", text):
        heads.add("sys/socket.h")
    if re.search(r"\bfd_set\b", text):
        heads.add("sys/select.h")
    if re.search(r"\bstat(?:64)?\b", text):
        heads.add("sys/stat.h")
    if re.search(r"\bFILE\b", text):
        heads.add("stdio.h")
    if re.search(r"\b(?:strtol|strtoul|strtoll|strtoull|atoi|atol|atof|strtod|strtof|"
                 r"malloc|calloc|realloc|free|signal)\b", text):
        heads.add("stdlib.h")
    if re.search(r"\b(?:signal|__sighandler_t|sigaction)\b", text):
        heads.add("signal.h")
    if re.search(r"\bdirent\b", text):
        heads.add("dirent.h")
    return [f"#include <{h}>" for h in sorted(heads)]


def _referenced(text: str) -> set[str]:
    """Every name a type spelling mentions (`std::vector<Item *>` -> std, vector, Item): the closure
    walks these, so a container member pulls its element type's layout along."""
    return {m.group(0) for m in re.finditer(r"[A-Za-z_]\w*", text or "")}


def _qualified_paths(text: str) -> set[str]:
    """The qualified type spellings in a declaration (`Format::String` in a member type)."""
    return {m.group(0) for m in re.finditer(r"(?<![\w:])(?:[A-Za-z_]\w*::)+[A-Za-z_]\w*", text or "")}


def _template_parts(text: str) -> tuple[str, list[str] | None]:
    """('std::map', ['unsigned int', 'ComPtr<X>']) for a template spelling, (text, None) otherwise.
    Top-level commas only: function-pointer parameters and nested templates stay whole."""
    t = " ".join((text or "").split())
    lt = t.find("<")
    if lt < 0:
        return t, None
    depth = paren = 0
    args: list[str] = []
    start = lt + 1
    for i in range(lt, len(t)):
        ch = t[i]
        if ch in "([":
            paren += 1
        elif ch in ")]":
            paren = max(0, paren - 1)
        elif paren == 0 and ch == "<":
            depth += 1
        elif paren == 0 and ch == ">":
            depth -= 1
            if depth == 0:
                args.append(t[start:i].strip())
                return t[:lt].strip(), [a for a in args if a]
        elif paren == 0 and depth == 1 and ch == ",":
            args.append(t[start:i].strip())
            start = i + 1
    return t, None


def _template_param_decl(args: list[str]) -> list[str]:
    """`DynamicArray<String,2,16>` -> `typename T0, int N1, int N2`."""
    params: list[str] = []
    ti = ni = bi = 0
    for arg in args:
        s = (arg or "").strip()
        if re.fullmatch(r"-?\d+", s):
            params.append(f"int N{ni}")
            ni += 1
        elif s in ("true", "false"):
            params.append(f"bool B{bi}")
            bi += 1
        else:
            params.append(f"typename T{ti}")
            ti += 1
    return params


def _split_scope(text: str) -> list[str]:
    """Split `Ns::Class::Method` on top-level `::` (template arguments stay whole)."""
    parts: list[str] = []
    start = angle = paren = bracket = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "<":
            angle += 1
        elif ch == ">":
            angle = max(0, angle - 1)
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(0, bracket - 1)
        elif angle == 0 and paren == 0 and bracket == 0 and text.startswith("::", i):
            parts.append(text[start:i])
            i += 2
            start = i
            continue
        i += 1
    parts.append(text[start:])
    return parts


def _callable_scope(display: str) -> tuple[str, str] | None:
    """`Ns::Class::Method(...)` -> (`Ns::Class`, `Method`)."""
    display = (display or "").strip()
    if not display.endswith(")"):
        return None
    depth = 0
    open_paren = -1
    for i in range(len(display) - 1, -1, -1):
        if display[i] == ")":
            depth += 1
        elif display[i] == "(":
            depth -= 1
            if depth == 0:
                open_paren = i
                break
    if open_paren <= 0:
        return None
    parts = _split_scope(display[:open_paren].strip())
    if len(parts) < 2:
        return None
    return "::".join(parts[:-1]), parts[-1]


def _wrap_namespace(scope: str, decl: str) -> str:
    """`Ns::Sub` + `void f();` -> `namespace Ns { namespace Sub { void f(); } }`."""
    parts = _split_scope(scope or "")
    if not parts or any(not _IDENT.fullmatch(p or "") for p in parts):
        return f"/* {decl}: namespace cannot be spelled */"
    return (" ".join(f"namespace {part} {{" for part in parts) + " " + decl + " "
            + "}" * len(parts))


def _norm_spaces(text: str) -> str:
    return " ".join((text or "").split())


def _template_entries_in(text: str, by_full: dict[str, dict]) -> list[dict]:
    """The concrete template specialisations spelled in a member/method type."""
    out: list[dict] = []
    for match in re.finditer(r"([A-Za-z_]\w*)\s*<", text or ""):
        start, depth = match.start(1), 0
        for j in range(match.end() - 1, len(text)):
            if text[j] == "<":
                depth += 1
            elif text[j] == ">":
                depth -= 1
                if depth == 0:
                    entry = by_full.get(sanitize(_norm_spaces(text[start:j + 1])))
                    if entry is not None:
                        out.append(entry)
                    break
    return out


def _template_primary(name: str, kind: str) -> str | None:
    base, args = _template_parts(name)
    if args is None or not args:
        return None
    params = _template_param_decl(args)
    if not params:
        return None
    return f"template <{', '.join(params)}> {kind} {base};"


def _template_decls(text: str) -> dict[str, int]:
    """{name: parameter count} for every `template<...> struct/class Name` in the header text. A
    template use with the wrong arity must degrade to opaque bytes: emitting it verbatim is what
    produced `lm::vector: too few template arguments` inside an otherwise valid projection."""
    out: dict[str, int] = {}
    for m in re.finditer(r"\btemplate\s*<([^<>]*(?:<[^<>]*>[^<>]*)*)>\s*(?:struct|class)\s+([A-Za-z_]\w*)",
                         text or ""):
        params = m.group(1).strip()
        if not params:  # explicit specialization
            continue
        depth, count = 0, 1
        for ch in params:
            if ch in "<([":
                depth += 1
            elif ch in ">)]":
                depth -= 1
            elif ch == "," and depth == 0:
                count += 1
        out[m.group(2)] = count
    return out


def _wrap(text: str, ns: list[str]) -> str:
    if not ns:
        return text
    return " ".join(f"namespace {p} {{" for p in ns) + "\n" + text + "\n" + "}" * len(ns)


_SCALARS = {"void", "bool", "char", "signed char", "unsigned char", "short", "unsigned short",
            "int", "unsigned int", "long", "unsigned long", "long long", "unsigned long long",
            "float", "double", "long double", "wchar_t", "size_t", "ssize_t", "ptrdiff_t",
            "uintptr_t", "intptr_t", "__int64", "__int32", "__int16", "__int8",
            "unsigned __int64", "unsigned __int32", "unsigned __int16", "unsigned __int8",
            "signed __int64", "signed __int32", "signed __int16", "signed __int8"}
_TYPEDEF_NAMES = {"uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t",
                  "int64_t", "time_t", "ssize_t", "off_t", "pid_t", "ino_t", "dev_t", "nlink_t",
                  "mode_t", "uid_t", "gid_t", "blksize_t", "blkcnt_t"}

# These are declared by the platform's own headers (pthread.h, cxxabi/unwind) once any normal
# Standard Library header is included. Re-declaring them after <cstdint> is a C++ redeclaration
# error (`__THROWNL` differs), even for a unit whose functions never call them.
_SYSTEM_RUNTIME_PREFIXES = ("pthread_", "_Unwind_", "__cxa_", "__gxx_personality")

# libc/POSIX layouts that a DWARF/PDB dump also contains. The platform headers define them, often
# with attributes the reconstructed text lacks; redefining one (timeval) makes every unit invalid.
_SYSTEM_TYPES = {
    "timeval", "timespec", "tm", "stat", "stat64", "sockaddr", "sockaddr_in", "sockaddr_in6",
    "sockaddr_un", "iovec", "msghdr", "cmsghdr", "pollfd", "epoll_event", "fd_set", "sigset_t",
    "pthread_attr_t", "pthread_mutex_t", "pthread_cond_t", "pthread_rwlock_t", "dirent", "FILE",
    "rusage", "utsname", "termios", "winsize", "passwd", "group", "hostent", "addrinfo",
}
_LIBC_STDLIB = {"strtol", "strtoul", "strtoll", "strtoull", "atoi", "atol", "atof",
                "strtod", "strtof", "malloc", "calloc", "realloc", "free", "signal"}
_WINDOWS_SYSTEM_TYPES = {
    "FILETIME", "LARGE_INTEGER", "ULARGE_INTEGER", "SYSTEMTIME", "SECURITY_ATTRIBUTES", "OVERLAPPED",
    "CRITICAL_SECTION", "GUID", "RECT", "POINT", "SIZE", "MSG", "WNDCLASS", "WNDCLASSEX", "HDC",
    "HINSTANCE", "HWND", "HMODULE", "HANDLE", "SOCKET", "WSADATA", "PROCESS_INFORMATION",
    "STARTUPINFO", "MEMORY_BASIC_INFORMATION", "EXCEPTION_RECORD", "CONTEXT", "LPVOID", "DWORD",
}
# Layouts in these namespaces belong to the toolchain's STL, not to the binary: emitting
# `std::_Atomic_int` or `template <> struct atomic<int>` next to `#include <atomic>` is a
# redefinition (C2766). The provider's declaration is the only correct spelling.
_PROVIDER_NAMESPACES = {"std", "__gnu_cxx", "__cxxabiv1"}


def _provider_type(t: dict) -> bool:
    ns = t.get("ns") or []
    name = (t.get("name") or "").strip()
    return (bool(ns) and ns[0] in _PROVIDER_NAMESPACES) or any(
        name.startswith(p + "::") for p in _PROVIDER_NAMESPACES)


def _target_format(analysis: dict) -> str:
    return str((analysis or {}).get("format") or "elf").lower()


def _system_types(analysis: dict) -> set[str]:
    fmt = _target_format(analysis)
    return _SYSTEM_TYPES | (_WINDOWS_SYSTEM_TYPES if fmt == "pe" else set())


def _runtime_prefixes(analysis: dict) -> tuple[str, ...]:
    """Runtime/ABI symbols whose declarations belong to platform headers, not this header."""
    if _target_format(analysis) == "pe":
        return ("_CxxThrowException", "__CxxFrameHandler", "_guard_", "_chkstk", "__security_",
                "_except_handler", "_RTC_")
    return _SYSTEM_RUNTIME_PREFIXES


def _base_of(text: str) -> tuple[str, bool]:
    """('TraceLog', True) from `const TraceLog &`: the bare type name, and whether it sits behind a
    pointer or reference (a forward declaration is enough then)."""
    t = " ".join((text or "").split())
    has_ptr = "*" in t or "&" in t
    m = re.match(r"^(.+?)(?:\s*[*&]+)?(?:\s*\[\d+\])*$", t)
    base = (m.group(1) if m else t).strip()
    base = re.sub(r"^(?:const|volatile)\s+", "", base)
    return base, has_ptr


def _qualify_types(txt: str, own_ns: tuple, by_name: dict, fwd_base: dict,
                   templates: dict[str, list[dict]] | None = None,
                   own_name: str = "") -> str:
    """Spell a type from another namespace with its full path.

    DWARF records `google::protobuf::Message`; the class is `ACME::Aurora::Core::Record`. Emitting
    the member's type as bare `Message` inside `namespace ACME::Aurora::Core` makes the generated
    header invalid even though a forward declaration for the right name exists. Qualification is
    target-agnostic: it uses the registry's namespaces for DWARF/PDB types and leaves already-qualified
    spellings, builtins and locally declared types alone."""
    own_ns = tuple(own_ns or ())

    def repl(m: re.Match) -> str:
        word = m.group(0)
        if word in _SCALARS or word in _TYPEDEF_NAMES:
            return word
        if own_name and word == own_name:
            # An unqualified self-reference (copy ctor, pointer-to-self member) names this class,
            # not whichever same-leaf entry the bare-name map happened to pick.
            return word
        if word in _STD_FORWARDS:
            # DWARF often stores a bare `shared_ptr<…>`; a boost::shared_ptr entry must not win
            # the bare-name lookup for a standard-library spelling.
            return "std::" + word
        t = by_name.get(word) or fwd_base.get(word)
        if t is None and templates:
            specs = templates.get(word) or []
            t = next((s for s in specs if tuple(s.get("ns") or ()) != own_ns),
                     specs[0] if specs else None)
        if t is None:
            if word in _STD_FORWARDS:
                return "std::" + word
            return word
        if not _spellable(t):
            tbase, targs = _template_parts(t.get("name") or "")
            if (targs is None or not _IDENT.fullmatch(tbase)
                    or not all(_IDENT.fullmatch(p or "") for p in t.get("ns") or [])):
                return word
        ns = tuple(t.get("ns") or ())
        if ns == own_ns:
            return word
        return "::" + "::".join([*ns, word])

    # `Foo::Bar` / `::Foo::Bar`: the leaf is already qualified; only rewrite free-standing names.
    return re.sub(r"(?<![\w:])([A-Za-z_]\w*)(?![\w])", repl, txt or "")


def _method_decl(t: dict, m: dict, usable, qualify=None) -> str | None:
    """`bool empty() const;` from the debug info's member-function inventory, None when the
    signature isn't spellable without more headers (templates, unresolved types)."""
    name = (m.get("name") or "").strip()
    if not name or _TEMPLATE.search(name):
        return None
    params = [sanitize(p) for p in (m.get("params") or [])]
    ret = sanitize(m.get("ret") or "").strip()
    if m.get("variadic"):
        if not params:  # `(...)` alone is not a valid parameter list in C++
            return None
        params.append("...")
    is_alloc = name.startswith(("operator new", "operator delete"))
    if is_alloc:
        # C++ requires size_t here, not IDA's MSVC spelling.  This is also what makes the
        # same generated class compile under g++ on an LP64 host.
        params = [re.sub(r"^(?:unsigned\s+)?(?:long long|int64_t|uint64_t|unsigned long)$",
                         "size_t", p) for p in params]
    if any(not p or (p != "..." and not usable(p)) for p in params) or (ret and not usable(ret)):
        return None
    if any("const const" in x for x in [*params, ret]):
        return None
    if any(re.fullmatch(r"(?:const_|reverse_)?iterator", x.strip()) for x in [*params, ret]):
        return None  # IDA attached an unrelated container's iterator methods to this type
    qual = qualify or (lambda x: x)
    params = [qual(p) for p in params]
    ret = qual(ret) if ret else ret
    ctor = name == t.get("name") or name == (t.get("name") or "").split("<", 1)[0]
    dtor = name.startswith("~")
    allocation = name.startswith(("operator new", "operator delete"))
    conversion = name.startswith("operator ") and not allocation  # `operator wchar_t const *`
    if not ctor and not dtor and not conversion and not ret:
        ret = "void"
    kw = "virtual " if m.get("virtual") else (
        "static " if m.get("static") and not (ctor or dtor or conversion) else "")
    ret_part = "" if ctor or dtor or conversion else f"{ret} "
    const = " const" if m.get("const") and not m.get("static") else ""
    return f"{kw}{ret_part}{name}({', '.join(params)}){const};"


_TYPE_MARK_BEGIN = "/* >>> decomp.wtf types — generated from the registry; edit the registry, not this block */"
_TYPE_MARK_END = "/* <<< decomp.wtf types */"


def strip_types(text: str) -> str:
    """The stored header without its generated types block (compile headers add a fresh one)."""
    return re.sub(rf"{re.escape(_TYPE_MARK_BEGIN)}.*?{re.escape(_TYPE_MARK_END)}\n?", "", text or "", flags=re.S)


_IDENT = re.compile(r"[A-Za-z_]\w*")


def _spellable(t: dict) -> bool:
    """Can this entry be spelled with plain identifiers? A qualified template spelling some producer
    split on '::' (ACME::…::DynamicArray<ACME::…::String,2,16>) must never render as
    `namespace … { namespace DynamicArray<ACME { … struct String,2,16>; }}}` — a stored header with
    that line doesn't parse, so every edit_context on the unit bounced (the agents then went reading
    the app's own source to find out why)."""
    if not _IDENT.fullmatch(t.get("name") or ""):
        return False
    return all(_IDENT.fullmatch(p or "") for p in t.get("ns") or [])


def type_block(analysis: dict, text: str, *, types: list[dict] | None = None,
               exclude: set[str] | None = None, full: bool = False,
               usage: str | None = None, aliases: set[str] | None = None) -> str:
    """Class/struct definitions from the binary's DWARF for the types this file's code names: real
    member names, offsets and sizes — the agents otherwise re-derive layouts from `[rdi+8]` per
    function and drift apart across files. `types` overrides the source (the registry's merged view:
    debug info + agent contributions); `exclude` drops names the compiled source declares itself;
    `full` walks the closure without the display path's small depth/size caps; `aliases` are
    `using` names (typically `using yield_context = …;` in the unit header) that are spellable even
    though they are not registry entries."""
    exclude = exclude or set()
    aliases = aliases or set()
    usage_text = text if usage is None else usage
    filter_methods = usage is not None

    def method_used(t: dict, m: dict) -> bool:
        """Keep virtual methods for vtable layout; otherwise only methods the source names.

        Without an explicit `usage` source the block is a complete type view (the registry
        editor and its tests need every declared method); a function-scoped header passes
        the source so unrelated methods cannot drag their parameter types into the closure."""
        name = (m.get("name") or "").strip()
        if not name or m.get("virtual"):
            return bool(name)
        if not filter_methods:
            return True
        leaf = (t.get("name") or "").split("<", 1)[0]
        if name == leaf or name == "~" + leaf:
            return re.search(rf"(?<![\w]){re.escape(leaf)}(?![\w])", usage_text) is not None
        if name.startswith("operator"):
            return False  # operators are not literal tokens in the source; avoid pulling their types
        return re.search(rf"(?<![\w]){re.escape(name)}(?![\w])", usage_text) is not None

    by_name: dict[str, dict] = {}
    fwd_base: dict[str, dict] = {}  # everything the debug info names, even when too big to define here
    decl_map: dict[str, dict] = {}  # entries carried as verbatim declaration text (salvaged)
    # A nested type (Outer::Inner where the path Outer is itself a type in the library) cannot be
    # spelled here: `namespace Outer {` next to the `struct Outer;` this same block forwards is a
    # C2757 redefinition cascade (it ICE'd cl on ORION's engine hubs; 3,917 names in the library
    # double as "namespaces" of other entries). Nested entries are skipped and member uses degrade
    # to the opaque byte form. Only exact path prefixes count, so a real namespace that shares its
    # leaf name with some class elsewhere stays untouched.
    _entries = list(types if types is not None else (analysis.get("types") or []))
    system_types = _system_types(analysis)
    template_by_name: dict[str, dict] = {}
    template_by_full: dict[str, dict] = {}
    template_by_leaf: dict[str, list[dict]] = {}
    for t in _entries:
        name = (t.get("name") or "").strip()
        ns = t.get("ns") or []
        base, args = _template_parts(name)
        if ("<" not in name or args is None or "(" in name or name in system_types
                or _provider_type(t)
                or not _IDENT.fullmatch(base) or not all(_IDENT.fullmatch(p or "") for p in ns)):
            continue
        key = "::".join([*ns, name])
        template_by_name[key] = t
        template_by_full.setdefault(sanitize(_norm_spaces(name)), t)
        template_by_leaf.setdefault(base.rsplit("::", 1)[-1], []).append(t)
    paths = {tuple([*(t.get("ns") or []), t.get("name") or ""]) for t in _entries
             if t.get("name") and "<" not in t["name"] and "(" not in t["name"]
             and not _provider_type(t) and _spellable(t)}

    def is_nested(t: dict) -> bool:
        path = tuple(t.get("ns") or [])
        return any(path[:i] in paths for i in range(1, len(path) + 1))

    for t in _entries:
        name = t.get("name") or ""
        if not name or "<" in name or "(" in name or name in exclude or name in system_types \
                or _provider_type(t) or not _spellable(t) or is_nested(t):
            continue
        if t.get("decl"):
            decl_map[name] = t
            continue
        prev = fwd_base.get(name)
        if prev is None or (t.get("ns") and not prev.get("ns")):
            fwd_base[name] = t
        if not t.get("size") or t["size"] > 0x2000:
            continue
        prev = by_name.get(name)
        if prev is None or len(t.get("members") or []) > len(prev.get("members") or []):
            by_name[name] = t

    by_path: dict[str, dict] = {}
    for t in _entries:
        name = t.get("name") or ""
        if not name or "<" in name or "(" in name or _provider_type(t) or not _spellable(t):
            continue
        by_path.setdefault("::".join([*(t.get("ns") or []), name]), t)

    def path_type(path: str):
        path = path.lstrip(":")
        direct = by_path.get(path)
        if direct is not None:
            return direct
        suffix = "::" + path
        matches = [(len(full), t) for full, t in by_path.items() if full.endswith(suffix)]
        return max(matches, key=lambda m: m[0])[1] if matches else None

    def mentioned(t: dict) -> bool:
        # `ACME::Aurora::Core::Name` must count: the old lookbehind excluded names right after ':', so the
        # closure silently missed every fully-qualified mention (the usual way real code names types).
        # The substring test is necessary for the regex and C-speed: it rejects almost every name in a
        # big library before the per-name pattern compile, which made this scan quadratic on ORION.
        name = t.get("name") or ""
        if name not in text:
            return False
        if name[:1].islower():
            # `OSMemory::Type type` mentions a *parameter* named `type`, not a global type named
            # `type`. Generic lowercase type entries are common in IDA's local types; seeding one
            # from a variable name dragged its whole member graph into the header. A real lowercase
            # type in `value *p` or `struct value` does not match this declarator shape.
            m = re.search(rf"(?<![:<\w])([A-Za-z_]\w*(?:::\w+)*)(?:\s*[*&])?\s+{re.escape(name)}\b", text)
            if m and m.group(1) not in ("struct", "class", "union", "enum", "typedef", "using",
                                        "namespace", "return", "new", "delete", "sizeof"):
                return False
        full = "::".join([*(t.get("ns") or []), name])
        for m in re.finditer(rf"(?<!\w){re.escape(name)}(?![\w])", text):
            scope_use = text[m.end():].lstrip().startswith("::")
            before = text[:m.start()]
            if re.search(r"\bnamespace\s+$", before):
                continue  # `namespace Base {`: a namespace, not this type
            pm = re.search(r"((?:[A-Za-z_]\w*::)*)$", before)
            chain = (pm.group(1) + name) if pm and pm.group(1) else name
            if chain == full or chain.endswith("::" + full):
                # `common::tracekit::TraceLogDefault::x` or a fully-qualified type use.
                return True
            if scope_use:
                continue  # `ACME::Obsidian::Base::String`: this Base is the namespace component
            if pm and pm.group(1):
                continue  # the same leaf under a different namespace is a different type
            return True  # an unqualified mention is a real use of this entry
        return False

    picked: dict[str, dict] = {}
    base_templates = _template_decls(text)
    # Extract identifiers once instead of asking `mentioned()` to scan the (often multi-megabyte)
    # text for every one of ~100k registry types: that fixed scan was the registry gate's 10-minute
    # cost. The full namespace/declarator check still runs, but only on plausible candidates.
    words = set(re.findall(r"[A-Za-z_]\w*", text))
    queue = [t for t in by_name.values() if t["name"] in words and mentioned(t)]
    queue += [t for t in template_by_name.values()
              if _template_parts(t["name"])[0].rsplit("::", 1)[-1] in words and mentioned(t)]

    def mention_pos(t: dict) -> int:
        full = "::".join([*(t.get("ns") or []), t.get("name") or ""])
        points = [text.find(t.get("name") or ""), text.find(full),
                  text.find((t.get("name") or "").rsplit("::", 1)[-1])]
        return min((p for p in points if p >= 0), default=10 ** 9)

    # The compact header has a 24-type cap. Mention order is a better priority than analysis
    # order: a callee prototype near the top of this function must get its types before a
    # library type that happens to sit earlier in the IDA database.
    queue.sort(key=mention_pos)
    cap = 10 ** 9 if full else 24
    for _depth in range(64 if full else 3):
        if not queue or len(picked) >= cap:
            break
        nxt = []
        def add_refs(text: str) -> None:
            paths = _qualified_paths(text)
            leaves = {p.rsplit("::", 1)[-1] for p in paths}
            for path in paths:
                exact = path_type(path)
                if exact is not None and exact is not t:
                    nxt.append(exact)
            for simple in _referenced(text):
                if simple in leaves:  # `Format::String` is not the unrelated bare `String`
                    continue
                if simple in by_name and by_name[simple] is not t:
                    nxt.append(by_name[simple])
            nxt.extend(x for x in _template_entries_in(text, template_by_full) if x is not t)

        for t in queue:
            key = "::".join([*t["ns"], t["name"]])
            if key in picked or len(picked) >= cap:
                continue
            picked[key] = t
            for m in t.get("members") or []:
                add_refs(m.get("type") or "")
            for m in t.get("methods") or []:  # methods name types too: the closure must follow them
                if not method_used(t, m):
                    continue
                for txt in [m.get("ret") or "", *(m.get("params") or [])]:
                    add_refs(txt)
            for b in t.get("bases") or []:  # a base class must be declared before the derived class
                add_refs(b.get("name") or b.get("type") or "")
        queue = nxt
    if not picked and not any(mentioned(t) for t in decl_map.values()):
        return ""

    groups: dict[tuple, list[dict]] = {}
    for t in picked.values():
        groups.setdefault(tuple(t["ns"]), []).append(t)
    picked_bare = {t["name"] for t in picked.values()}
    picked_qualified = {"::".join([*(t.get("ns") or []), t["name"]]) for t in picked.values()}
    picked_template_heads = {
        _template_parts(t["name"])[0].rsplit("::", 1)[-1]
        for t in picked.values() if "<" in (t.get("name") or "")
    }
    picked_template_texts = {
        sanitize(_norm_spaces(t["name"])) for t in picked.values() if "<" in (t.get("name") or "")
    }
    fwd_used: set[tuple[tuple, str, str]] = set()

    def usable(txt: str, need_ptr: bool = False) -> bool:
        """Can this type be spelled safely in the block? A type is usable only when every name in
        it is declared here (or is a scalar, a fixed typedef, a std type, a block-defined template
        with matching arity, or a forward-declarable class behind a pointer). The old `"std::" in txt`
        shortcut said yes to `std::map<int, Microsoft::WRL::ComPtr<X>>` — emitting an undeclared
        ComPtr and cascading into C2653/C2976/C1003. Undeclared or arity-mismatched templates and
        unknown namespaced types degrade to opaque byte storage instead."""
        t = " ".join((txt or "").split())
        if not t:
            return False
        if t in aliases or t.rsplit("::", 1)[-1] in aliases:
            return True  # a `using` alias declared in this unit's header
        if re.fullmatch(r"[-+]?(?:0[xX][0-9A-Fa-f]+|\d+)[uUlL]*", t):
            return True  # non-type template argument
        if "(*" in t:  # function pointer: self-contained when every name in it is known
            known = _SCALARS | _TYPEDEF_NAMES | picked_bare | set(base_templates)
            ids = set(_IDENT.findall(t)) - {"const", "volatile", "void", "std", "__fastcall", "__stdcall",
                                            "__cdecl", "__thiscall", "signed", "unsigned", "int", "char",
                                            "short", "long", "float", "double", "bool", "size_t", "__int64"}
            return all(i in known or i in by_name or i in fwd_base for i in ids)
        base, args = _template_parts(t)
        if args is not None:
            base = re.sub(r"^(?:const|volatile)\s+", "", base).strip()
            base = re.sub(r"^(?:enum|struct|class)\s+", "", base).strip().rstrip("*& ").strip()
            leaf = base.rsplit("::", 1)[-1]
            if base in ("shared_ptr", "weak_ptr", "std::shared_ptr", "std::weak_ptr"):
                # These hold an incomplete type; a forward declaration is enough. Treat the
                # argument as a pointer target instead of requiring a complete by-value type.
                # DWARF often stores the bare `shared_ptr`, without the `std::` prefix.
                return len(args) == 1 and usable(args[0].strip() + " *")
            if base.startswith("std::"):
                return all(usable(a) for a in args)
            # A template only the analysis names is not a definition: a by-value member of it
            # would be incomplete. Require this exact specialisation in the block.
            leaf = base.rsplit("::", 1)[-1]
            candidate = sanitize(_norm_spaces(f"{leaf}<{','.join(args)}>"))
            if candidate in picked_template_texts:
                return all(usable(a) for a in args)
            if leaf in picked_bare or leaf in base_templates:
                n = base_templates.get(leaf)
                if n is not None and len(args) != n:  # a stale/arity-mismatched spelling
                    return False
                return all(usable(a) for a in args)
            return False  # a template only the debug info names: cannot forward-declare its params
        if re.match(r"^(?:const\s+)?std::\w+", t):
            return True  # non-template std type (the block carries its include)
        base, has_ptr = _base_of(t)
        base = re.sub(r"^(?:const|volatile)\s+", "", base).strip()
        base = re.sub(r"\s+(?:const|volatile)$", "", base).strip()
        base = re.sub(r"^(?:enum|struct|class)\s+", "", base).strip()
        if not base or "<" in base:
            return False
        base_leaf = base.rsplit("::", 1)[-1]
        if base in _SCALARS or base in _TYPEDEF_NAMES or base in picked_qualified:
            return True
        if "::" not in base and (base in picked_bare or base_leaf in picked_bare):
            return True
        t_entry = (path_type(base) if "::" in base
                   else (by_name.get(base) or fwd_base.get(base)
                         or by_name.get(base_leaf) or fwd_base.get(base_leaf)))
        if t_entry is not None and (has_ptr or not need_ptr):
            if not _spellable(t_entry) or is_nested(t_entry):  # a declaration here would conflict or dangle
                return False
            fwd_used.add((tuple(t_entry.get("ns") or []), t_entry.get("kind") or "class",
                          t_entry.get("name") or base_leaf))
            return True
        return False

    def signature_local(m: dict) -> bool:
        """A method whose signature only needs types this block already has (or can forward-declare).
        Registry-added methods like `Player *clone()` must render even when the source never names
        them; methods that would drag in templates/std specialisations stay hidden unless used."""
        for txt in [m.get("ret") or "", *(m.get("params") or [])]:
            txt = sanitize(txt)
            if not txt or txt == "...":
                continue
            if "std::" in txt or _template_parts(txt)[1] is not None:
                return False
            if not usable(txt):
                return False
        return True

    body: list[str] = []
    primaries: dict[tuple, list[str]] = {}
    seen_primary: set[tuple] = set()
    for t in sorted(picked.values(), key=lambda x: (tuple(x.get("ns") or []), x.get("name") or "")):
        name = t.get("name") or ""
        if "<" not in name:
            continue
        base, args = _template_parts(name)
        key = (tuple(t.get("ns") or []), base)
        if key in seen_primary:
            continue
        kind = "union" if t.get("kind") == "union" else (
            "class" if t.get("kind") == "class" else "struct")
        primary = _template_primary(name, kind)
        if primary:
            primaries.setdefault(tuple(t.get("ns") or []), []).append(primary)
            seen_primary.add(key)
    for ns, decls in sorted(primaries.items()):
        if ns:
            body.append(" ".join(f"namespace {part} {{" for part in ns))
        body += decls
        if ns:
            body.append("}" * len(ns))

    all_within = {"::".join([*(t.get("ns") or []), t["name"]]): t for t in picked.values()}
    all_leaf_paths: dict[str, list[str]] = {}
    for full, t in all_within.items():
        all_leaf_paths.setdefault(t["name"], []).append(full)

    def resolve_dep(spelling: str) -> tuple[str, dict] | None:
        spelling = (spelling or "").strip()
        if spelling in all_within:
            return spelling, all_within[spelling]
        leaf = spelling.rsplit("::", 1)[-1]
        found = all_leaf_paths.get(leaf) or []
        return (found[0], all_within[found[0]]) if len(found) == 1 else None

    # A namespace group can depend on a type in another group by value
    # (`google::protobuf::Message` holds `internal::HasBits<1>`). Emitting groups in
    # alphabetical order put the holder first and GCC rejected the incomplete member.
    group_deps: dict[tuple, set[tuple]] = {ns: set() for ns in groups}
    for ns, ts in groups.items():
        for t in ts:
            for m in t.get("members") or []:
                base, has_ptr = _base_of(m.get("type") or "")
                if has_ptr:
                    continue
                dep = resolve_dep(base)
                if dep is not None and tuple(dep[1].get("ns") or []) != ns:
                    group_deps[ns].add(tuple(dep[1].get("ns") or []))
    remaining_groups = set(groups)
    ordered_groups: list[tuple] = []
    while remaining_groups:
        placed_groups = set(ordered_groups)
        ready = sorted(ns for ns in remaining_groups if group_deps[ns] <= placed_groups)
        if not ready:  # a by-value cycle; keep the old deterministic order
            ordered_groups += sorted(remaining_groups)
            break
        ordered_groups += ready
        remaining_groups -= set(ready)

    for ns in ordered_groups:
        ts = groups[ns]
        if ns:
            body.append(" ".join(f"namespace {part} {{" for part in ns))
        # a class whose members hold another picked class by value must come after it
        within = {"::".join([*(t.get("ns") or []), t["name"]]): t for t in ts}
        leaf_paths: dict[str, list[str]] = {}
        for full, t in within.items():
            leaf_paths.setdefault(t["name"], []).append(full)

        def dep_of(spelling: str) -> str | None:
            spelling = (spelling or "").strip()
            if spelling in within:
                return spelling
            leaf = spelling.rsplit("::", 1)[-1]
            found = leaf_paths.get(leaf) or []
            return found[0] if len(found) == 1 else None

        def deps(t):
            out = set()
            full_t = "::".join([*(t.get("ns") or []), t["name"]])
            for m in t.get("members") or []:
                mtype = m.get("type") or ""
                base, has_ptr = _base_of(mtype)
                dep = dep_of(base)
                if not has_ptr and dep and dep != full_t:
                    out.add(dep)
                if not has_ptr:
                    # Template member spellings are qualified in the PDB
                    # (`ACME::…::SmallPointer<…>`) while `within` holds the bare name.
                    for full, other in within.items():
                        if full != full_t and re.search(
                                rf"(?<![\w]){re.escape(other['name'])}(?![\w])", mtype):
                            out.add(full)
            for b in t.get("bases") or []:
                dep = dep_of((b.get("name") or b.get("type") or "").rsplit("::", 1)[-1])
                dep = dep or dep_of(b.get("name") or b.get("type") or "")
                if dep and dep != full_t:
                    out.add(dep)
            return out

        remaining = sorted(ts, key=lambda t: t["name"])
        ordered: list[dict] = []
        while remaining:
            placed = {"::".join([*(x.get("ns") or []), x["name"]]) for x in ordered}
            ready = [t for t in remaining if deps(t) <= placed]
            if not ready:  # a by-value cycle; emit it alphabetically and let the gate judge
                ordered += remaining
                break
            ordered += ready
            remaining = [t for t in remaining if t not in ready]
        for t in ordered:
            if "<" in (t.get("name") or ""):
                _, targs = _template_parts(t["name"])
                if targs and not all(usable(a) for a in targs):
                    continue  # a missing argument type makes `template <> ...<T>` unspellable
            kw = "union" if t.get("kind") == "union" else (
                "class" if t.get("kind") == "class" else "struct")
            bases: list[str] = []
            if kw != "union":
                for b in t.get("bases") or []:
                    bname = re.sub(r"^(?:class|struct|union)\s+", "",
                                   (b.get("name") or b.get("type") or "").strip())
                    if bname and "<" not in bname and "(" not in bname:
                        bases.append(("virtual " if b.get("virtual") else "") + "public " + bname)
            body.append(f'/* size 0x{t["size"]:x} */')
            prefix = "template <> " if "<" in (t.get("name") or "") else ""
            body.append(f'{prefix}{kw} {t["name"]}' + (f' : {", ".join(bases)}' if bases else "")
                        + ' {' + (" public:" if kw == "class" else ""))
            methods = t.get("methods") or []
            virtual_class = any(m.get("virtual") for m in methods)
            renderable_virtual = any(
                m.get("virtual") and _method_decl(t, m, usable) is not None for m in methods)
            if virtual_class and not renderable_virtual:
                # Only anchor when every virtual signature is unspellable; otherwise the first
                # real virtual method already occupies slot 0 and the anchor would shift every
                # vtable call by one slot (isRun +0x38 instead of +0x30).
                body.append("    virtual void _dcore_vtable_anchor();")
            members = t.get("members") or []
            ptr_size = 4 if str(analysis.get("arch") or "").lower() in (
                "x86", "i386", "arm", "mips", "ppc") else 8
            cursor = ptr_size if virtual_class else 0
            for i, m in enumerate(members):
                bit_size = int(m.get("bit_size") or 0)
                if bit_size:
                    bit_start = int(m.get("bit_start") if m.get("bit_start") is not None
                                    else (m.get("off") or 0) * 8)
                    off = bit_start // 8
                    if off > cursor:
                        body.append(f"    unsigned char _pad{cursor:x}[{off - cursor}];")
                    mname = (m.get("name") or "").strip()
                    if not re.match(r"^[A-Za-z_]\w*$", mname):
                        mname = f"_bits{off:x}"
                    mtype = sanitize(m.get("type") or "").strip()
                    own_ns = tuple(t.get("ns") or ())
                    btype = (_qualify_types(mtype, own_ns, by_name, fwd_base, template_by_leaf,
                                            own_name=t.get("name") or "")
                             if mtype and (usable(mtype) or "std::" in mtype) else "unsigned int")
                    body.append(f"    {btype} {mname} : {bit_size};")
                    cursor = max(cursor, (bit_start + bit_size + 7) // 8)
                    continue
                off = int(m.get("off") or 0)
                end = int(members[i + 1]["off"]) if i + 1 < len(members) else int(t.get("size") or 0)
                size = int(m.get("size") or 0) or max(1, end - off)
                mname = (m.get("name") or "").strip()
                if mname.startswith("_vptr"):
                    if virtual_class:
                        # the vptr is the compiler's own, generated by the virtual methods below —
                        # declaring it as data too would occupy offset 0 twice and shift every member
                        cursor = off + size
                        continue
                    mname = "_vptr"
                elif not re.match(r"^[A-Za-z_]\w*$", mname):
                    mname = f"_member{off:x}"
                if off > cursor:
                    body.append(f"    unsigned char _pad{cursor:x}[{off - cursor}];")
                mtype = sanitize(m.get("type") or "").strip()
                suffix = ""
                if m.get("count"):  # set_member(count=)/remove_member spell arrays as a count
                    suffix = f"[{int(m['count'])}]"
                else:  # IDA prints array members postfix ("unsigned int[1]"); C wants the brackets on the name
                    mm = re.match(r"^(.*\S)\s*((?:\[\d*\])+)$", mtype)
                    if mm:
                        mtype, suffix = mm.group(1).strip(), mm.group(2)
                is_template = _template_parts(mtype)[1] is not None
                if (mtype and ">::" not in mtype
                        and (_TYPENAME.match(mtype) or "std::" in mtype or is_template)
                        and usable(mtype, need_ptr=True)):
                    own_ns = tuple(t.get("ns") or ())
                    body.append(f"    {_qualify_types(mtype, own_ns, by_name, fwd_base, template_by_leaf, own_name=t.get('name') or '')} {mname}{suffix};")
                else:
                    amem = int(m.get("align") or 0)
                    if not amem:
                        known = by_name.get(mtype) or fwd_base.get(mtype)
                        amem = int((known or {}).get("align") or 0)
                    if not amem and size >= 8:
                        amem = 8  # pthread_mutex_t/string-sized opaque storage is 8-aligned
                    prefix = f"alignas({amem}) " if amem > 1 else ""
                    body.append(f"    {prefix}unsigned char {mname}[{size}];  /* {mtype or '?'} */")
                cursor = off + size
            for s in t.get("statics") or []:
                sname = (s.get("name") or "") if isinstance(s, dict) else str(s)
                stype = sanitize(s.get("type") or "").strip() if isinstance(s, dict) else ""
                ssuffix = ""
                if isinstance(s, dict) and s.get("count"):
                    ssuffix = f"[{int(s['count'])}]"
                else:
                    mm = re.match(r"^(.*\S)\s*((?:\[\d*\])+)$", stype)
                    if mm:
                        stype, ssuffix = mm.group(1).strip(), mm.group(2)
                if sname and stype and (_TYPENAME.match(stype) or "std::" in stype) and usable(stype):
                    own_ns = tuple(t.get("ns") or ())
                    vis = (s.get("visibility") or "").strip() if isinstance(s, dict) else ""
                    attr = (f'__attribute__((visibility("{vis}"))) '
                            if vis and str(analysis.get("format") or "").lower() != "pe" else "")
                    body.append(f"    static {attr}{_qualify_types(stype, own_ns, by_name, fwd_base, template_by_leaf, own_name=t.get('name') or '')} {sname}{ssuffix};  /* defined elsewhere */")
                elif sname:
                    body.append(f"    // static member {sname} ({stype or 'type unknown'}), defined elsewhere")
            # An empty base/class has size 1 in C++ but no object bytes; padding it would
            # make it non-empty and shift the first derived member off offset 0.
            if cursor < t["size"] and (members or t["size"] > 1):
                body.append(f"    unsigned char _pad{cursor:x}[{t['size'] - cursor}];")
            seen: set[tuple] = set()
            decls: list[str] = []
            for m in methods:
                if not method_used(t, m) and not signature_local(m):
                    continue
                sig = (m.get("name"), tuple(m.get("params") or []), bool(m.get("const")), bool(m.get("static")))
                if sig in seen:
                    continue
                seen.add(sig)
                decl = _method_decl(t, m, usable,
                                    lambda txt, ns=tuple(t.get("ns") or ()),
                                    nm=t.get("name") or "":
                                    _qualify_types(txt, ns, by_name, fwd_base, template_by_leaf,
                                                   own_name=nm))
                if decl:
                    decls.append(decl)
                elif m.get("linkage") and not _TEMPLATE.search(m.get("name") or ""):
                    decls.append(f'// {m["name"]}(...): declared in the debug info; signature needs types '
                                 f'this header doesn\'t have')
            if decls:
                body.append("")
                body.append("    /* member functions, declared from the binary's debug info */")
                body += [f"    {d}" for d in decls]
            body.append("};")
        if ns:
            body.append("}" * len(ns))
    for name, t in sorted(decl_map.items()):
        if name not in by_name and mentioned(t):
            body.append("")
            body.append(_wrap(t["decl"], t.get("ns") or []))

    lines = ["/* ------- class layouts from the binary's debug info: member names, offsets and sizes",
             " * are the original's (DWARF byte offsets). Use these; don't re-derive layouts. ------- */"]
    lines += std_includes("\n".join(body))
    for ns, ts in sorted(groups.items()):
        plain = [t for t in ts if "<" not in (t.get("name") or "")]
        if not plain:
            continue
        fwd = " ".join(f'{t["kind"]} {t["name"]};' for t in sorted(plain, key=lambda t: t["name"]))
        lines.append(" ".join(f"namespace {part} {{" for part in ns) + " " + fwd + " " + "}" * len(ns) if ns else fwd)
    extra: dict[tuple, list[str]] = {}
    for ns, kind, name in sorted(fwd_used):
        if name not in picked_bare and "<" not in name:
            extra.setdefault(ns, []).append(f"{kind} {name};")
    for ns, decls in sorted(extra.items()):
        lines.append(" ".join(f"namespace {part} {{" for part in ns) + " " + " ".join(decls)
                     + " " + "}" * len(ns) if ns else " ".join(decls))
    lines.append("")
    lines += body
    return _TYPE_MARK_BEGIN + "\n" + "\n".join(lines) + "\n" + _TYPE_MARK_END


def context_block(analysis: dict, units: list[str], *, language: str,
                  only_eas: set[int] | None = None) -> list[str]:
    """The declaration part of a header: what the listed files' functions call into, plus the
    signatures of the files' own functions as comments. Unit headers and the reconstruction's
    merged headers are both built on this.  `only_eas` restricts the callee set to one
    function's edges, which is what the per-function compile header uses instead of every
    callee of the whole unit."""
    by_ea = {f["ea"]: f for f in analysis.get("functions") or []}
    files = (analysis.get("graph") or {}).get("files") or {}
    own_eas = (set(only_eas) if only_eas is not None else
               {ea for u in units for ea in (files.get(u) or {}).get("functions", [])})
    own_eas = {ea for ea in own_eas if ea in by_ea}
    own = [by_ea[ea] for ea in sorted(own_eas, key=lambda e: by_ea[e].get("display") or "")]
    # A demangled C++ callee can name a nested type the debug info has no entry for
    # (`ACME::Aurora::Core::TimeUtils::Timer` vs `ACME::Aurora::Core::Timer`). Emitting that prototype makes
    # every function in the unit uncompilable, including ones that never call it. Only qualified
    # paths the type table knows are safe to spell; everything else is a comment the agent can fix.
    type_paths = {"::".join([*(t.get("ns") or []), t.get("name") or ""])
                  for t in analysis.get("types") or [] if t.get("name")}

    def spellable_callee(sig: str) -> bool:
        sig = _hidden_this(sig)
        if "@<" in sig or ">::" in sig:
            return False
        for path in re.findall(r"(?<![\w:])(?:[A-Za-z_]\w*::)+[A-Za-z_]\w*", sig):
            if path.startswith(("std::", "__gnu_cxx::", "__cxxabi::")):
                continue
            if path not in type_paths:
                return False
        return True
    callees: dict[str, dict] = {}
    for edge in analysis.get("edges") or []:
        if edge["ea"] in own_eas:
            for to in edge.get("to", []):
                fn = by_ea.get(to)
                if fn is None or fn["ea"] in own_eas:
                    continue
                name = fn.get("display") or fn.get("name") or ""
                is_import = name.startswith(".") and name[1:].isidentifier()  # e.g. `.printf`
                if fn.get("provenance") == "auto" and not is_import:
                    continue  # sub_XXXX: nothing honest to declare
                if name and name not in callees:
                    callees[name] = fn

    base = ", ".join(Path(u).name or u for u in units) if units else "?"
    fmt = _target_format(analysis)
    posix = fmt in ("elf", "macho")
    lines = [f"/* context.h for {base} — generated from the original binary (IDA + debug info).",
             " * Declares what this file's functions call into so they compile on their own.",
             " * edit_context edits are regression-tested against every matched function. */", ""]
    if language == "c++":
        # native targets compile on Linux: the real <cstdint> has the platform's spellings
        # (int64_t is `long` there, not `long long` — hand-rolled typedefs collide with it)
        lines.append("#include <cstdint>")
        lines.append("#include <cstddef>")  # size_t for class allocation operators
    else:
        # C has no <cstdint>; the C spellings are the target's own (stdint.h is universal)
        lines += ["#include <stdint.h>", "#include <stddef.h>"]
    lines.append("")
    block: list[str] = []      # C linkage / imports
    cpp_block: list[str] = []  # C++ namespace or global declarations
    for name in sorted(callees):
        fn = callees[name]
        sig = fn.get("signature") or ""
        # `.printf` is how IDA spells a PLT thunk: it is a real import, declared under its plain name.
        # Skipping it made agent-written calls to printf non-variadic — and a variadic call needs
        # `xor eax, eax` (AL = 0), so the function could never match byte for byte.
        is_import = name.startswith(".") and name[1:].isidentifier()
        if fn.get("provenance") == "auto" and not is_import:
            continue  # sub_XXXX: nothing honest to declare
        if is_import and not sig:
            continue  # no signature at all: a guessed declaration hurts more than none
        decl = name[1:] if is_import else name
        if (_target_format(analysis) != "pe"
                and decl.rsplit("::", 1)[-1] in _LIBC_STDLIB):
            continue  # libc owns these; the manual spelling is ABI-wrong (long long vs long)
        if posix and decl.startswith("pthread_"):
            continue  # the platform's pthread.h owns the declaration; our spelling only conflicts
        if language == "c++" and decl.startswith(_runtime_prefixes(analysis)):
            continue  # ABI/compiler runtime; the platform headers or compiler own it
        if language == "c++" and (decl.startswith("std::") or decl.startswith("__gnu_cxx::")):
            continue  # library internals: the standard headers own them, and inline calls need no spelling
        if language == "c++" and (fn.get("language") or "c") == "c++":
            parsed = _callable_scope(name)
            scope, member = parsed if parsed else ("", decl)
            if parsed and scope in type_paths:
                continue  # a class method is declared by the class definition, not as a free function
            if not parsed:
                if spellable_callee(sig) and "<" not in decl:
                    cpp_block.append(prototype(decl, sig, cpp=True))
                elif "<" in decl:
                    cpp_block.append(f"/* {decl}: library template specialization; primary not in this header */")
                else:
                    cpp_block.append(f"/* {decl}: signature needs types this header doesn't have */")
                continue
            if not all(_IDENT.fullmatch(part or "") for part in _split_scope(scope)):
                cpp_block.append(f"/* {decl}: namespace cannot be spelled without a type this header lacks */")
                continue
            if not spellable_callee(sig):
                cpp_block.append(f"/* {decl}: signature needs types this header doesn't have */")
                continue
            if "<" in member:
                cpp_block.append(f"/* {decl}: library template specialization; primary not in this header */")
                continue
            cpp_block.append(_wrap_namespace(scope, prototype(member, sig, cpp=True)))
            continue
        if not spellable_callee(sig):
            block.append(f"/* {decl}: signature needs types this header doesn't have */")
            continue
        block.append(prototype(decl, sig, cpp=language == "c++"))
    system_text = "\n".join(f"{name} {fn.get('signature') or ''}" for name, fn in callees.items())
    all_decls = "\n".join([*block, *cpp_block])
    lines += system_includes(system_text + "\n" + all_decls, language, analysis)
    lines += std_includes(all_decls)
    if block:
        if language == "c++":
            lines.append('extern "C" {')
            lines += [f"    {line}" for line in block]
            lines.append("}")
        else:
            lines += block
        lines.append("")
    if cpp_block:
        lines += cpp_block
        lines.append("")
    if own:
        lines.append("/* defined in this file (write these with these signatures): */")
        for fn in own:
            name = fn.get("display") or fn.get("name") or ""
            if not name:
                continue
            parts = signature_parts(fn.get("signature") or "")
            if parts:
                lines.append(f"/* {parts[0]} {name}({parts[1]}); */")
            else:
                lines.append(f"/* {name}(...): IDA had no signature for it */")
    return lines


def function_context(analysis: dict, fn: dict, *, language: str) -> list[str]:
    """Context declarations for one function: its callees and its own signature as a comment."""
    return context_block(analysis, [fn.get("file") or ""], language=language,
                         only_eas={fn["ea"]})


def function_header(analysis: dict, fn: dict, *, language: str, types: list[dict] | None = None,
                    source: str = "") -> str:
    """A self-contained type/context header for one function, before registry entries are added."""
    lines = function_context(analysis, fn, language=language)
    seed = "\n".join(lines) + "\n" + source
    block = type_block(analysis, seed, types=types)
    return "\n".join(lines) + (("\n\n" + block) if block else "")


def c_type_block(analysis: dict, text: str, *, types: list[dict] | None = None,
                 exclude: set[str] | None = None, full: bool = False) -> str:
    """C struct/union layouts from DWARF/PDB. C has no namespaces, methods or vptr: emit tags,
    members and typedef aliases only — the same header must compile with gcc, clang and MSVC for
    every target architecture. Unknown member types degrade to opaque bytes, exactly like C++."""
    exclude = exclude or set()
    system_types = _system_types(analysis)
    by_name: dict[str, dict] = {}
    for t in (types if types is not None else (analysis.get("types") or [])):
        name = t.get("name") or ""
        if not name or "<" in name or "(" in name or name in exclude or name in system_types \
                or not _spellable(t) or t.get("kind") not in ("struct", "union") or t.get("ns"):
            continue
        prev = by_name.get(name)
        if prev is None or len(t.get("members") or []) > len(prev.get("members") or []):
            by_name[name] = t

    def mentioned(name: str) -> bool:
        return bool(name) and re.search(rf"(?<!\w){re.escape(name)}(?!\w)", text or "") is not None

    picked: dict[str, dict] = {}
    queue = [t for t in by_name.values() if mentioned(t["name"])]
    cap = 10 ** 9 if full else 24
    for _depth in range(64 if full else 4):
        if not queue or len(picked) >= cap:
            break
        nxt = []
        for t in queue:
            if t["name"] in picked or len(picked) >= cap:
                continue
            picked[t["name"]] = t
            for m in t.get("members") or []:
                base, _ = _base_of(m.get("type") or "")
                base = re.sub(r"^(?:enum|struct|union|class)\s+", "", base).strip()
                if base in by_name and base not in picked:
                    nxt.append(by_name[base])
        queue = nxt
    if not picked:
        return ""

    # typedef aliases make both `struct Name *` and `Name *` spellable; a tag typedef before the
    # definition is valid C and leaves a pointer to an incomplete type legal.
    lines = [_TYPE_MARK_BEGIN,
             "#include <stdint.h>",
             "#include <stddef.h>"]
    for name in sorted(picked):
        kind = "union" if picked[name].get("kind") == "union" else "struct"
        lines.append(f"typedef {kind} {name} {name};")
    lines.append("")
    for name in sorted(picked):
        t = picked[name]
        kind = "union" if t.get("kind") == "union" else "struct"
        lines.append(f"/* size 0x{int(t.get('size') or 0):x} */")
        lines.append(f"{kind} {name} {{")
        members = t.get("members") or []
        cursor = 0
        for i, m in enumerate(members):
            off = int(m.get("off") or 0)
            end = int(members[i + 1]["off"]) if i + 1 < len(members) else int(t.get("size") or 0)
            size = max(1, end - off)
            mname = (m.get("name") or "").strip()
            if not re.match(r"^[A-Za-z_]\w*$", mname):
                mname = f"_member{off:x}"
            if off > cursor:
                lines.append(f"    unsigned char _pad{cursor:x}[{off - cursor}];")
            mtype = sanitize(m.get("type") or "").strip()
            suffix = ""
            if m.get("count"):
                suffix = f"[{int(m['count'])}]"
            else:
                mm = re.match(r"^(.*\S)\s*((?:\[\d*\])+)$", mtype)
                if mm:
                    mtype, suffix = mm.group(1).strip(), mm.group(2)
            base, has_ptr = _base_of(mtype)
            base = re.sub(r"^(?:enum|struct|union|class)\s+", "", base).strip()
            usable = bool(mtype) and (_TYPENAME.match(mtype) or "std::" in mtype)
            known = base in picked or base in _SCALARS or base in _TYPEDEF_NAMES
            if usable and (known or has_ptr and base in by_name):
                lines.append(f"    {mtype} {mname}{suffix};")
            else:
                lines.append(f"    unsigned char {mname}[{size}];  /* {mtype or '?'} */")
            cursor = off + size
        if cursor < int(t.get("size") or 0):
            lines.append(f"    unsigned char _pad{cursor:x}[{int(t.get('size') or 0) - cursor}];")
        lines.append("};")
    lines.append(_TYPE_MARK_END)
    return "\n".join(lines)


def unit_header(analysis: dict, unit: str, *, language: str, types: list[dict] | None = None) -> str:
    """The context header for one file: what its functions call, plus its own expected shapes.
    `types` is the registry's merged view when the caller has one (agent contributions included)."""
    lines = context_block(analysis, [unit], language=language)
    if language == "c++":
        block = type_block(analysis, "\n".join(lines), types=types)
        if block:
            # layouts/forward declarations must exist before the callee prototypes that spell them
            return block + "\n\n" + "\n".join(lines) + "\n"
    elif language == "c":
        block = c_type_block(analysis, "\n".join(lines), types=types)
        if block:
            return block + "\n\n" + "\n".join(lines) + "\n"
    lines.append("")
    return "\n".join(lines)
