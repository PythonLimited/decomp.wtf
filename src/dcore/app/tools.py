"""The tools a decompiling agent gets, served over MCP to CLI agents and called directly by the
built-in API agent. Every tool works on the project the agent was started on."""

from __future__ import annotations

import collections
import json
import re
from importlib import resources
from typing import Callable

import anyio
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .. import __version__
from ..core.network import Agent, NetworkError
from ..core.engine import Engine

# Which agents have a tool call running inside this app right now. The session runner's stall
# watchdog reads it: silence while a tool works (a docker compile, the first IDA draft fetch)
# is legitimate; silence with nothing in flight means the model's stream has died.
_INFLIGHT: collections.Counter = collections.Counter()


def tool_active(agent_name: str) -> bool:
    return _INFLIGHT[agent_name] > 0

GUIDES = {
    "workflow": "the matching loop, reading diffs, priorities",
    "data": "globals, strings, tables, floats, data you define",
    "structs": "working out struct layouts from offsets",
    "naming": "naming functions and data",
    "cpp": "decompiling C++: classes, vtables, constructors, inlines, name mangling",
    "x86": "x86 and MSVC (Windows, macOS Intel): calling conventions, SEH, matching MSVC output",
    "aarch64": "AArch64 and Clang (Android, Apple silicon): registers, matching Clang output",
    "similarity": "finding similar functions and reusing matched code",
}

INSTRUCTIONS = """\
decomp.wtf: you are decompiling a shipped program the user owns into C/C++ that compiles to exactly the
same machine code. Your code is compiled with the original compiler and diffed against the program's own
bytes: score 0 means byte-identical, and the function is saved as matched.
Start with project_info, then claim_function -> compile_and_diff (repeat). guide(topic) has know-how.
Everything runs on the user's computer. The program's code is the user's: never publish it anywhere.
"""

WORK_PROMPT = """\
You are a decompilation agent in decomp.wtf, working on {title}. Other agents may be working on other
functions of the same program at the same time; the tools keep you from colliding.

Your job: turn functions of this program into C/C++ that compiles to *exactly* the original machine code.
Use only the decomp tools. Work through {count} function(s) — one batch claim — then stop:

Everything you need to know comes from these tools. Never read the original files (exe/pdb/i64) or any of the
machine's directories to look something up: symbol names and xrefs are ida(action="globals"/"xrefs"), layouts are
ida(action="types"), bytes are read_data, disassembly and pseudocode are ida(action="disasm"/"decompile") — a
function name gives its whole body in one call, don't chunk it by address — and what the header declares is
get_context with list_decls. The session's filesystem is fenced — reads outside the workdir fail by design, and
the tools answer everything those files would have. If a declaration you must fix lives in the frozen legacy
header, promote_legacy(function=…, old=<exact text>, new=<corrected text>) moves it into an entry (a wrong
`struct`/`class` tag changes the MSVC mangling: U vs V); a *type* the seed defines and the registry should own
is freed with promote_type(name, function=…). Class members are never file-scope prototypes: add_method(name,
method, ret=…, params=…, static=…) declares them inside the class, and a qualified `Ns::Class::f(...)` written
at file scope is refused with that guidance.

1. claim_function(count={count}) gives you the next function(s): bytes, callers, machine-generated drafts
   (IDA's decompilation) to start from and notes. Small functions mostly match on the first try: take the
   batch and judge them together.
2. get_context(function) shows the header exactly as this function's next compile will see it — entries,
   the legacy text's visible part, then the fresh type projection (the same pipeline compile_and_diff runs),
   so you can check what a declare/undeclare/promote/edit_decls edit did before spending a compile. Headers are
   generated: declare(body, kind) adds a unit-scope entry, undeclare(name|entry) removes one,
   edit_decls(remove=…, add=…) applies several atomically (the repair path when a unit is wedged by more than
   one entry), list_decls shows them; edit_context is the legacy text editor. Types are shared: search_types()
   before hand-rolling a struct; declare_type/edit_type add or fix one, and members/methods belong in the class
   (add_method, edit_type set_member/set_method) — if the class is still defined in the frozen seed, promote_type
   first so the registry's definition is what renders. Every function that uses a type is re-verified by the judge.
   Need more than the brief? ida(action=...) asks the database directly: xrefs (who references this, what it
   references), disasm at any address, decompile, IDA's type library, globals, strings, segments.
3. Write the function and judge it: compile_and_diff(function="a, b, c", source=<definitions>) for a batch,
   one name for one. A submission is exactly the function — first line to closing brace: constants go
   inside the body, declarations go into the header with declare (class members: add_method). Registry and
   header are gated: a change that breaks any matched function is refused, with what those functions reported.
4. Score 0 = matched and saved. If the diff says the original calls/reads an address IDA left
   unnamed and your object names it, use name_function(name=..., address=0x...) for code or
   name_data(name=..., address=0x...) for globals once; the judge resolves it from then on. Read
   the diff: '<' '>' missing/extra instructions, 'i' operands, 'o'
   order, 'r' registers, 's' stack. Fix structure first, registers last. The workflow and {compiler_guide}
   guides are below.
5. No better after about 20 compiles in a row? release_function with precise notes (what you tried, what
   is left) and claim the next one. A handoff before ~20 compiles needs a filed report(kind='bug') that
   documents the blocker; otherwise keep working. Reading notes is not a substitute for trying.

Pure C/C++: no inline asm, and no type definitions or helper declarations in the submission (the tools
refuse them). Be brief in your messages: work, don't narrate.

If a tool misbehaves or a capability is missing and you cannot work around it, file it instead of giving up
quietly: report(kind="bug"|"need", title=<one line>, detail=<what you tried, what you expected>, function=…).
Identical titles merge, so the recurring walls sort to the top of the project's todo list.
"""


def _guide(topic: str = "") -> str:
    topic = topic.strip().lower()
    if topic not in GUIDES:
        listing = "\n".join(f"- {k}: {v}" for k, v in GUIDES.items())
        return f"Guides (call guide with one of these topics):\n{listing}"
    return resources.files("dcore.app").joinpath("guide", f"{topic}.md").read_text(encoding="utf-8")


def _native(net: Engine, slug: str, what: str) -> str:
    native = net.native_slug(slug)
    if not native:
        raise NetworkError(f"{what} is for native programs (ELF/PE): the type registry tracks the classes and "
                           f"structs the reconstructed code compiles against")
    return native


def _entry_remove(text) -> list:
    """`#25, FromInt64, 29` -> [25, 'FromInt64', 29] (ids may carry a leading #)."""
    out: list = []
    for part in str(text or "").replace("\n", ",").split(","):
        item = part.strip().lstrip("#")
        if not item:
            continue
        out.append(int(item) if item.isdigit() else part.strip())
    return out


def _entry_add(text) -> list[dict]:
    """JSON array (or one object) of {kind, body} entries for an atomic edit_decls."""
    raw = str(text or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except ValueError as e:
        raise NetworkError('add must be JSON: [{"kind": "prototype", "body": "int f(void);"}]') from e
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or any(not isinstance(d, dict) or "body" not in d for d in data):
        raise NetworkError('add must be a JSON array of objects with a body, e.g. '
                           '[{"kind": "prototype", "body": "int f(void);"}]')
    return data


def project_info(net: Engine, slug: str) -> str:
    wish = net.instructions(slug)
    text = _project_info(net, slug)
    return text + (f"\nThe user's instructions for this project (they come first):\n{wish}" if wish else "")


def _project_info(net: Engine, slug: str) -> str:
    return net.native.info(net.native_slug(slug))


# name -> handler(net, agent, slug, **args); every handler returns text for the model
def _claim(net: Engine, agent: Agent, slug: str, function: str, strategy: str, count: int = 1) -> str:
    """A claim; one asked for that's matched, hand-written assembly or someone else's is the next free function
    instead (an agent asking for those has nothing better to do than the next one, and is told why). count > 1: a
    batch of small ones."""
    strategy = strategy or "easiest"
    if not function and int(count or 1) > 1:
        return net.claim_many(agent, slug, int(count), strategy)
    try:
        return net.claim(agent, slug, function or None, strategy)
    except NetworkError as e:
        if not function or not re.search(r"already matched|is hand-written assembly|is claimed by", str(e)):
            raise
        return f"({e}. Here's the next free function instead.)\n\n" + net.claim(agent, slug, None, strategy)


def _split_names(text: str) -> list[str]:
    """Top-level commas only: C++ signatures carry commas inside their parameter lists, and a plain
    split would turn `Malloc(unsigned __int64, int)` into two phantom function names."""
    out: list[str] = []
    depth, cur = 0, []
    for ch in text or "":
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return [n for n in out if n]


def _compile(net: Engine, agent: Agent, slug: str, function: str, source: str, flags: str = "") -> str:
    """compile_and_diff; several names ("a, b, c") judge several definitions sent together. `flags` probes one
    native function's build with those compiler flags (nothing is recorded)."""
    names = _split_names(function)
    if len(names) <= 1:
        return net.compile_and_diff(agent, names[0] if names else function, source, slug, flags=flags)
    return net.attempt_many(agent, [net.resolve_function(agent, slug, n) for n in names], source, slug)


HANDLERS: dict[str, Callable[..., str]] = {
    "project_info": lambda net, agent, slug: project_info(net, slug),
    "strict_rejudge": lambda net, agent, slug, limit=0:
        net.native.strict_rejudge(net._project(slug), int(limit) or None),
    "set_mode": lambda net, agent, slug, function, mode, note="":
        net.set_mode(agent, function, mode, note, slug),
    "set_signature": lambda net, agent, slug, function, ret, params="", const="", static="", virtual="", note="":
        net.native.set_signature(agent, _native(net, slug, "set_signature"), function, ret,
                                 params=params, const=const, static=static, virtual=virtual, note=note),
    "claim_function": lambda net, agent, slug, function="", strategy="", count=1:
        _claim(net, agent, slug, function, strategy, count),
    "get_function": lambda net, agent, slug, function: net.get_function(function, slug, agent),
    "compile_and_diff": lambda net, agent, slug, function, source, flags="":
        _compile(net, agent, slug, function, source, flags),
    "set_build_flags": lambda net, agent, slug, flags, function="", scope="function":
        _set_build_flags(net, agent, slug, flags, function or None, scope),
    "search_types": lambda net, agent, slug, query="", ns="", member="", kind="", used_by="", limit=20:
        net.native.search_types(_native(net, slug, "search_types"), query, ns, member, kind, used_by, limit),
    "get_type": lambda net, agent, slug, name:
        net.native.get_type(_native(net, slug, "get_type"), name),
    "declare_type": lambda net, agent, slug, name, kind="struct", size="", note="", session="":
        net.native.edit_type(agent, _native(net, slug, "declare_type"), "declare", session=session,
                             name=name, kind=kind, size=size or None, note=note),
    "edit_type": lambda net, agent, slug, action, name, member="", mtype="", at="", count=1, new_name="",
        other="", scope="", kind="", size="", note="", params="", static="", visibility="",
        const="", session="":
        net.native.edit_type(agent, _native(net, slug, "edit_type"), action, session=session, name=name,
                             member=member, mtype=mtype, params=params, static=static,
                             visibility=visibility, const=const,
                             at=(int(str(at), 0) if str(at) not in ("", "None") else None), count=count,
                             new_name=new_name, other=other, scope=scope, kind=kind,
                             size=(int(str(size), 0) if str(size) not in ("", "None") else None), note=note),
    "declare_opaque": lambda net, agent, slug, name, decl, size="", align="", trivial="", note="":
        net.native.declare_opaque(agent, _native(net, slug, "declare_opaque"), name, decl,
                                  size=size, align=align, trivial=trivial, note=note),
    "lock_registry": lambda net, agent, slug, wait=120:
        net.native.lock_registry(agent, _native(net, slug, "lock_registry"), wait),
    "unlock_registry": lambda net, agent, slug, session, action="commit":
        net.native.unlock_registry(agent, _native(net, slug, "unlock_registry"), session, action),
    "release_function": lambda net, agent, slug, function, notes: net.release(agent, function, notes, slug),
    "get_context": lambda net, agent, slug, function="": net.get_context(slug, function or None),
    "name_function": lambda net, agent, slug, name, address, note="":
        net.native.name_function(agent, net._project(slug), name, address, note),
    "name_data": lambda net, agent, slug, name, address, note="":
        net.native.name_data(agent, net._project(slug), name, address, note),
    "edit_context": lambda net, agent, slug, old, new, message, function="":
        net.edit_context(agent, slug, old, new, message, function or None),
    "read_data": lambda net, agent, slug, what, length=64: net.read_data(slug, what, length),
    "declare": lambda net, agent, slug, body, kind="prototype", function="":
        net.declare_entry(agent, slug, body, kind, function or None),
    "undeclare": lambda net, agent, slug, name="", entry=0, function="":
        net.undeclare_entry(agent, slug, name or "", entry or None, function or None),
    "edit_decls": lambda net, agent, slug, remove="", add="", function="":
        net.edit_entries(agent, slug, _entry_remove(remove), _entry_add(add), function or None),
    "list_decls": lambda net, agent, slug, function="":
        net.list_entries(agent, slug, function or None),
    "promote_legacy": lambda net, agent, slug, old, new="", kind="raw", function="":
        net.promote_legacy(agent, slug, old, new, kind, function or None),
    "promote_type": lambda net, agent, slug, name, function="", message="":
        net.promote_type(agent, slug, name, function or None, message),
    "add_method": lambda net, agent, slug, name, method, ret="void", params="", static="false", note="":
        net.native.edit_type(agent, _native(net, slug, "add_method"), "set_method", name=name, member=method,
                             mtype=ret, params=params, static=static, note=note),
    "report": lambda net, agent, slug, kind, title, detail="", function="":
        net.report_issue(agent, slug, kind, title, detail, function or None),
    "ida": lambda net, agent, slug, action, query="", count=40:
        net.native.ida_lookup(slug, action, query, int(count)),
    "list_functions": lambda net, agent, slug, status="open", limit=40, query="":
        net.list_functions(slug, status, limit, query),
    "add_note": lambda net, agent, slug, text, function="": net.add_note(agent, slug, text, function or None),
    "search_notes": lambda net, agent, slug, query: net.search_notes(slug, query),
    "guide": lambda net, agent, slug, topic="": _guide(topic),
}

REGISTRY_TOOLS = {"search_types", "get_type", "declare_type", "edit_type", "add_method",
                  "promote_type", "lock_registry", "unlock_registry"}  # native programs only


def _set_build_flags(net: Engine, agent: Agent, slug: str, flags: str, function: str | None = None,
                     scope: str = "function") -> str:
    native = net.native_slug(slug)
    if not native:
        raise NetworkError("set_build_flags is for native programs (ELF/PE): console projects pick their "
                           "compiler when the game is imported")
    return net.native.set_flags(agent, native, flags, function=function, scope=scope)


def tool_names(native: bool = False) -> list[str]:
    """The tools an agent on this project sees: everything, minus the registry for non-native ones."""
    skip = set() if native else set(REGISTRY_TOOLS)  # the registry tracks a binary's own types
    return [n for n in HANDLERS if n not in skip]


def _named(net: Engine, agent: Agent, slug: str, args: dict) -> dict:
    """Function names as agents write them (a plain symbol that repeats across files, symbol@unit, Class::method)
    turned into the stored name, preferring the function the agent holds."""
    if args.get("function") and "," not in args["function"]:  # (several are resolved one by one, see _compile)
        args = {**args, "function": net.resolve_function(agent, slug, args["function"])}
    return args


def call(net: Engine, agent: Agent, slug: str, name: str, args: dict) -> str:
    """Run one tool for the built-in agent; errors come back as text the model can act on."""
    if name not in HANDLERS:
        return f"error: unknown tool {name!r}"
    try:
        net.renew_claims(agent, slug)  # active tool use keeps the claimed function theirs
    except NetworkError:
        pass
    try:
        return HANDLERS[name](net, agent, slug, **_named(net, agent, slug, args))
    except NetworkError as e:
        return f"error: {e}"
    except TypeError as e:
        return f"error: bad arguments for {name}: {e}"


# Antigravity CLI otherwise finds MCP tools on demand (an extra step each, through its generic dispatcher):
# decomp.wtf's tools are all there is to the job, so they are loaded up front.
ALWAYS_LOAD = {"antigravity/alwaysLoad": True}


def build_mcp(net: Engine, agent_of: Callable[[Context], tuple[Agent, str]]) -> MCPServer:
    """MCP server for CLI agents. `agent_of` maps a request to (agent, project slug)."""
    mcp = MCPServer(name="decomp", title="decomp.wtf", instructions=INSTRUCTIONS, version=__version__)

    async def run(ctx: Context, tool: str, **args) -> str:
        # `tool`, not `name`: tool arguments arrive through **args and several tools (get_type,
        # declare_type, edit_type) take an argument literally named `name` — it must not collide
        # with this helper's own parameter.
        try:
            agent, slug = agent_of(ctx)
        except NetworkError as e:
            raise ToolError(str(e)) from None
        counting = agent is not None  # tests dispatch with a fake context that has no agent
        if counting:
            _INFLIGHT[agent.name] += 1
            try:
                net.renew_claims(agent, slug)  # an MCP agent's tool call is proof it is still working
            except NetworkError:
                pass
        try:
            return await anyio.to_thread.run_sync(lambda: HANDLERS[tool](net, agent, slug, **_named(net, agent, slug, args)))
        except NetworkError as e:
            raise ToolError(str(e)) from None
        finally:
            if counting:
                _INFLIGHT[agent.name] -= 1

    @mcp.tool(meta=ALWAYS_LOAD)
    async def project_info(ctx: Context) -> str:
        """Which game you're working on, its compiler, and progress so far."""
        return await run(ctx, "project_info")

    @mcp.tool(meta=ALWAYS_LOAD)
    async def strict_rejudge(ctx: Context, limit: int = 0) -> str:
        """Re-run every matched function against the current judge without changing its status.

        Use after a judge/renderer change. `limit` audits only the first N matched functions.
        """
        return await run(ctx, "strict_rejudge", limit=limit)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def claim_function(ctx: Context, function: str = "", strategy: str = "", count: int = 1) -> str:
        """Claim the next function to decompile (or a specific one by name or address).

        Returns its assembly, the best previous attempt and notes from earlier agents, plus (ROM projects)
        calls, data and a machine-made draft or (forks) the current diff and its source file. Each compile
        renews the claim.

        Args:
            function: optional name or address (0x80001234) of a specific function
            strategy: finish (forks' default: the files closest to being linked first), easiest (fewest
                instructions; ROM projects' default), closest (nearly matched already), hardest, random
            count: up to 6: small functions come as a batch (neighbours in one file) to write together and
                judge in one compile_and_diff; a big one comes alone
        """
        return await run(ctx, "claim_function", function=function, strategy=strategy, count=count)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def get_function(ctx: Context, function: str) -> str:
        """Show any function (by name or address): assembly, status, best attempt, notes. Read matched
        functions to learn how this codebase is written."""
        return await run(ctx, "get_function", function=function)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def compile_and_diff(ctx: Context, function: str, source: str, flags: str = "") -> str:
        """Compile your code for `function` and diff it against the original; score 0 = byte-identical.

        ROM projects: compiled with the game's compiler (context.h included), linked at the function's
        address and compared with the ROM. Forks: send the complete definition (plus any #include "...",
        prototypes, externs or #pragma lines it needs); it replaces the function in its source file, which is
        built with the project's build system and diffed with objdiff. Several functions ("a, b, c"): send all
        their definitions in one source; each is judged on its own.
        Native programs: a submission is exactly the function — first line to closing brace — compiled
        against this file's context.h; its types come from the registry (search_types/declare_type) and
        declarations from the header (edit_context). `flags` builds this one attempt with those compiler
        flags as a probe — **nothing is recorded** — so you can find the original build's optimization
        settings (e.g. the project is at -O0 and the target was clearly -O2). A byte-identical probe is
        the answer; adopt it with set_build_flags.

        Args:
            flags: optional compiler flags to probe with for this one compile (native, open functions only)
        """
        return await run(ctx, "compile_and_diff", function=function, source=source, flags=flags)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def set_build_flags(ctx: Context, flags: str, function: str = "", scope: str = "function") -> str:
        """Set the compiler flags compiles are judged with (native programs), e.g. "-O2 -fno-strict-aliasing".

        With `function` (the default), the flags are saved **on that function**: probe it with
        compile_and_diff(..., flags="…"), then adopt the winning set. Other functions in the same file
        keep their own flags — two functions can genuinely need different optimisation levels.
        `scope="file"` pins the whole source file instead. Without `function`, the flags become the
        project default for every file/function that has no override. Gated like a header edit: every
        matched function whose flags change is recompiled and the change is rejected if any stops matching.

        Args:
            flags: the compiler flags, e.g. "-O3 -fno-strict-aliasing"; empty clears a function override
            function: optional; save the flags on this function (default) or its file (scope="file")
            scope: "function" (default) or "file"
        """
        return await run(ctx, "set_build_flags", flags=flags, function=function, scope=scope)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def search_types(ctx: Context, query: str = "", ns: str = "", member: str = "",
                           kind: str = "", used_by: str = "", limit: int = 20) -> str:
        """Find the types the code is built against (native programs): classes, structs, enums, unions.

        Search by name fragment, namespace, a member (its name or type), kind, or the function that uses
        it. The registry starts as the binary's debug info and grows from what agents work out — check it
        before hand-rolling a struct, and use it to answer "what type is my self pointer?": search by the
        member you spotted (member="next_ptr") or by used_by the function that handed it to you.

        Args:
            query: name fragment, e.g. "DoubleLink" (empty lists everything)
            ns: namespace prefix, e.g. "ACME::Aurora::Core"
            member: a member name or type fragment, e.g. "next_ptr" or "Node *"
            kind: struct | class | union | enum | typedef
            used_by: a function name fragment — only types its source mentions
            limit: max rows
        """
        return await run(ctx, "search_types", query=query, ns=ns, member=member, kind=kind,
                         used_by=used_by, limit=limit)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def get_type(ctx: Context, name: str) -> str:
        """One registry type: member-by-member layout with offsets, where it came from (the binary's debug
        info or an agent), and the matched functions a change to it would re-verify. Bare names resolve
        only when unambiguous — give the qualified name when the answer lists candidates.

        Args:
            name: type name, e.g. "DoubleLinkNode" or "ACME::Aurora::Core::DoubleLinkNode"
        """
        return await run(ctx, "get_type", name=name)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def declare_type(ctx: Context, name: str, kind: str = "struct", size: int = 0, note: str = "",
                           session: str = "") -> str:
        """Add a type to the shared registry — for classes/structs the debug info doesn't describe (stripped
        binaries) or pruned ones the code still references. Then add its fields with edit_type(set_member).

        Nothing lands unverified: the edit is applied to a candidate registry, every matched function whose
        compile environment would change is recompiled and re-judged, and it is kept only if they all still
        match byte-identically — a rejected one reports what broke. With a `session` (from lock_registry)
        the edit is staged instead: several related edits verify once, on unlock_registry.

        Args:
            name: qualified name, e.g. "ACME::Aurora::Core::SkipListNode" (namespace = scope, so types don't
                collide across the project; rename/move later with edit_type(action="move"))
            kind: struct | class | union | enum | typedef
            size: total size in bytes if you know it (from the allocation site, e.g. operator new(0x48))
            note: where you saw it — allocation site, vtable address, which function's this it is
            session: a lock_registry token: stage now, verify once on unlock_registry
        """
        return await run(ctx, "declare_type", name=name, kind=kind, size=size, note=note, session=session)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def edit_type(ctx: Context, action: str, name: str, member: str = "", mtype: str = "",
                        at: str = "", count: int = 1, new_name: str = "", other: str = "",
                        scope: str = "", size: int = 0, note: str = "", params: str = "",
                        static: str = "", visibility: str = "", const: str = "",
                        session: str = "") -> str:
        """Edit a registry type. Gated: every matched function whose compile environment changes is
        recompiled in the form it will live in and re-judged — kept only if all still match byte-identically.

        Actions:
          set_kind      — kind="class" or "struct": MSVC mangles a pointer by the type's *definition* kind
                          (PEAV vs PEAU), so a debug-info tag that disagrees with the binary's symbol is
                          fixed here; add_method/edit_type changes render from the same definition
          set_member    — add or replace the field at `at` (the offset from the assembly: [rdi+8] -> at="8"),
                          e.g. member="count_" mtype="uint32_t" at="64"; count= for arrays (char buf[16] -> count=16)
          set_method    — declare a member function: member="GetSystemTotalSize" mtype="unsigned __int64"
                          static="true" params=""; params is the comma-separated list ("" or "void" = none).
                          Add const="true" for a const member. This is how a call to a static member
                          gets its C++ mangled name right
          remove_method — drop a method the debug info declared (member="Name", params=… for one
                          overload). Use it when an implicit constructor makes the class non-aggregate
                          and the original code aggregate-initialized it.
          set_static    — declare a static data member: member="enable_" mtype="bool" (no offset — statics
                          are not part of the layout; the header renders it, calls mangle from it).
                          Add visibility="hidden" for a hidden ELF global.
          rename_member — member="old_name" (or "0x<offset>") new_name="better_name" (member names don't
                          change bytes, so this is safe when the layout is right)
          remove_member — member="name": the bytes stay, the name goes opaque (unsigned char _gap…)
          set_size      — size=0x48 (the total the allocator gave it)
          move          — scope="ACME::Aurora::Core" (namespaces are the type's scope; wrong-scope types are the
                          usual cause of "not declared" in a compile; the old scope stops rendering)
          hide | unhide — hide suppresses a type the debug info knows but the header shouldn't carry
                          (unhide takes the exact qualified key)
          merge         — other="<the other type>": try to unify two agent-declared types. The gate decides:
                          if every consumer of both still matches, treating them as one is consistent with
                          all verified code; if something breaks, the failure shows which field proves they differ.

        Args:
            action: set_member | set_method | remove_method | set_static | rename_member | remove_member | set_size | move | hide | unhide | merge
            name: the type (bare names only when unambiguous)
            member: member name — a method name for set_method/remove_method; a static's name for set_static; or "0x<offset>" for rename_member
            mtype: the member's type for set_member — any int type, char, void*, pointers/refs, arrays,
                or std:: types (std::vector<Item *> works; the right #include comes along);
                set_method's return type; set_static's type
            at: byte offset for set_member
            count: array count for set_member
            params: set_method's parameter list, comma-separated (empty/void = none);
                remove_method: narrows the removal to one overload (empty = all overloads)
            static: set_method: "true" for a static member function
            new_name: rename_member target
            other: merge partner
            scope: namespace for move, e.g. "ACME::Aurora::Core"
            size: bytes for set_size
            note: why (stored on the entry; the next agent reads it)
            session: a lock_registry token: stage now, verify once on unlock_registry (use it when
                making several related edits — one verification for the batch, and nobody else
                changes the registry under you)
        """
        return await run(ctx, "edit_type", action=action, name=name, member=member, mtype=mtype, at=at,
                         count=count, new_name=new_name, other=other, scope=scope, size=size, note=note,
                         params=params, static=static, visibility=visibility, const=const, session=session)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def set_signature(ctx: Context, function: str, ret: str, params: str = "", const: str = "",
                            static: str = "", virtual: str = "", note: str = "") -> str:
        """Edit one function's declaration without touching its body. A class method goes through the
        gated registry; a free/namespace function replaces its prototype in the unit header. This is
        the first-class path for `header`-mode functions and for fixing a wrong parameter/return
        spelling. The target's linkage is still the judge; a declaration that mangles differently
        fails as "the object does not define …", not as a silent pass.

        Args:
            function: exact function name, e.g. "ACME::Aurora::Core::Clock::now()"
            ret: return type, e.g. "void" or "std::string const *"
            params: comma-separated parameter list; "" or "void" means none
            const: "true" for a const member function
            static: "true" for a static member function
            virtual: "true" for a virtual member function
            note: why (stored for the next agent)
        """
        return await run(ctx, "set_signature", function=function, ret=ret, params=params, const=const,
                         static=static, virtual=virtual, note=note)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def declare_opaque(ctx: Context, name: str, decl: str, size: str = "", align: str = "",
                             trivial: str = "", note: str = "") -> str:
        """Declare a project-global opaque third-party type (Boost, protobuf, OpenSSL, …) so a
        signature or class can name it without the real library headers.

        The text renders as a **prelude before every unit's type block**, so an alias is visible to
        class methods that use it. Store a stub + alias, for example:

            namespace acme { namespace thirdparty {
            class executor;
            template<class T, class U>
            class executor_binder { alignas(8) unsigned char opaque_[16]; };
            template<class T>
            class basic_yield_context { alignas(8) unsigned char opaque_[8]; };
            }}
            using yield_context = acme::thirdparty::basic_yield_context<
                acme::thirdparty::executor_binder<void (*)(void), acme::thirdparty::executor>>;

        The emitted symbol is still checked against the target's linkage; a wrong namespace/template
        arity fails as "the function's symbol isn't in the object", not as a silent pass. By-value
        opaque types should carry size/align/trivial (the ABI class); pointer/reference-only types
        need none. Pass decl="" to remove the declaration.

        Args:
            name: project-global key, e.g. "acme::thirdparty::yield_context"
            decl: the prelude text (full namespace/template stub and alias); "" removes it
            size: byte size of a by-value opaque type, if known
            align: alignment of a by-value opaque type, if known
            trivial: "true"/"false" — trivially copyable/destructible (ABI class), if known
            note: why this stub is right (stored for the next agent)
        """
        return await run(ctx, "declare_opaque", name=name, decl=decl, size=size, align=align,
                         trivial=trivial, note=note)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def lock_registry(ctx: Context, wait: int = 120) -> str:
        """Take the registry for a batch of related edits (classes/structs/enums in native programs).

        While you hold it, other agents' registry edits wait their turn — nothing changes under you.
        Stage edits with declare_type(session=…) / edit_type(session=…): each is validated immediately
        but not verified; unlock_registry then verifies the whole batch in ONE pass (one gate run for
        many edits). A rejected batch stays staged so you can fix it and commit again; abort discards it.
        The lock is leased (~10 minutes, renewed by each staged edit) — if you go quiet it expires by
        itself, so it can never wedge the project. Single edits don't need this; they verify on their own.

        Args:
            wait: seconds to wait for another agent's session to end before giving up (0 = don't wait)
        """
        return await run(ctx, "lock_registry", wait=wait)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def unlock_registry(ctx: Context, session: str, action: str = "commit") -> str:
        """End a registry session: commit verifies every staged edit (all matched functions affected
        must still re-judge byte-identical — one pass for the batch), abort throws the batch away.

        Args:
            session: the token lock_registry returned
            action: commit | abort
        """
        return await run(ctx, "unlock_registry", session=session, action=action)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def release_function(ctx: Context, function: str, notes: str) -> str:
        """Hand a function off after ~20 compiles without progress, or with a filed report(kind='bug')
        documenting a blocker. Notes are required: what you tried, what is left. Your best attempt is
        kept for the next agent. Earlier handoffs are refused."""
        return await run(ctx, "release_function", function=function, notes=notes)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def get_context(ctx: Context, function: str = "") -> str:
        """The header this function's next compile will receive, rendered exactly (entries + legacy
        visible part + fresh projection — the same pipeline compile_and_diff uses). Read it after a
        declare/undeclare/promote_legacy edit to see what changed before compiling."""
        return await run(ctx, "get_context", function=function)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def name_function(ctx: Context, name: str, address: str, note: str = "") -> str:
        """Give an address IDA left unnamed a symbol spelling the judge can resolve.

        Use this when a diff says the original calls an unnamed address and your object calls a name
        that is not in the project symbol table. This is an alias, not a rename: it is stored on the
        project and used by both the judge and the header renderer.
        """
        return await run(ctx, "name_function", name=name, address=address, note=note)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def name_data(ctx: Context, name: str, address: str, note: str = "") -> str:
        """Give an unnamed data address the spelling the rebuilt header uses.

        When a diff says the original loads `.data+0x...` and your object references a global name
        the project does not know, bind that name to the address once. The judge and header
        renderer then resolve it like any analysis symbol.
        """
        return await run(ctx, "name_data", name=name, address=address, note=note)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def edit_context(ctx: Context, old: str, new: str, message: str, function: str = "") -> str:
        """Edit the shared header: replace `old` (must occur exactly once) with `new`, or append `new` when
        old is "". Accepted only if every matched function still matches. Add prototypes and structs here."""
        return await run(ctx, "edit_context", old=old, new=new, message=message, function=function)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def declare(ctx: Context, body: str, kind: str = "prototype", function: str = "") -> str:
        """Declare a UNIT-SCOPE fact the unit compiles against — a free function, a global/static, a
        typedef/using, an include, a note. Not for class members: `Ns::Class::method(...)` at file
        scope never compiles (it is refused) — add members with add_method, and if the class is still
        frozen in the seed, promote_type first. `function` picks the unit. Validated and gated like
        header edits: a declaration breaking a matched function is withdrawn."""
        return await run(ctx, "declare", body=body, kind=kind, function=function)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def undeclare(ctx: Context, name: str = "", entry: int = 0, function: str = "") -> str:
        """Remove a declaration entry by its declared name or its entry id (gated: a removal that
        breaks a matched function is restored automatically, at its original position)."""
        return await run(ctx, "undeclare", name=name, entry=entry, function=function)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def edit_decls(ctx: Context, remove: str = "", add: str = "", function: str = "") -> str:
        """Apply several declaration edits to one unit atomically — the repair path when a unit is
        wedged by more than one entry (removing either alone would still break every compile, so
        single edits are correctly refused). `remove`: comma-separated entry ids (#25) or declared
        names. `add`: JSON array of {"kind", "body"}, e.g.
        [{"kind":"prototype","body":"int f(void);"}]. The whole resulting header is gated once:
        either every matched function still matches, or nothing changes."""
        return await run(ctx, "edit_decls", remove=remove, add=add, function=function)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def list_decls(ctx: Context, function: str = "") -> str:
        """List the live declaration entries behind this unit's generated header."""
        return await run(ctx, "list_decls", function=function)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def promote_legacy(ctx: Context, old: str, new: str = "", kind: str = "raw",
                             function: str = "") -> str:
        """Move a declaration out of the frozen legacy header into the generated entries — the only
        sanctioned way to edit frozen text. `old` must occur exactly once in the stored header; `new`
        (default: same) becomes an entry of `kind`. Gated like every declaration. Use it when the seed
        declared a type with the wrong tag (`struct X` vs `class X` changes the MSVC mangling U→V)."""
        return await run(ctx, "promote_legacy", old=old, new=new, kind=kind, function=function)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def promote_type(ctx: Context, name: str, function: str = "", message: str = "") -> str:
        """Hand a type from the frozen legacy header to the registry: the stored definition is
        removed (gated) and the generated projection renders the registry's version instead. After
        this, edit_type/add_method changes actually reach the compile — the fix for "the seed
        definition shadows the registry". The registry must already know the type (debug info or
        declare_type). `function` picks the unit that holds the definition."""
        return await run(ctx, "promote_type", name=name, function=function, message=message)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def add_method(ctx: Context, name: str, method: str, ret: str = "void", params: str = "",
                         static: str = "false", note: str = "") -> str:
        """Add or replace a MEMBER FUNCTION on a class/struct in the type registry — the right way to
        declare something like `Ns::String::Replace`. The registry renders it inside the class, so the
        C++ mangling and the compile agree. params is comma-separated (""/void = none); static="true"
        for a static member. If the class is still defined in the frozen seed (see get_context), call
        promote_type(name) first so the registry's definition is the one that renders. Gated."""
        return await run(ctx, "add_method", name=name, method=method, ret=ret, params=params,
                         static=static, note=note)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def report(ctx: Context, kind: str, title: str, detail: str = "", function: str = "") -> str:
        """File a wall that is the stack's, not the function's: kind="bug" (a tool misbehaves, or an error
        you cannot work around) or kind="need" (a capability that is missing). One-line title; detail says
        what you tried and what you expected. Identical titles merge — it is the project's todo list."""
        return await run(ctx, "report", kind=kind, title=title, detail=detail, function=function)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def read_data(ctx: Context, what: str, length: int = 64) -> str:
        """Hex dump of the binary's data at an address, a function name, or a named global/static
        (`s_something`, `g_something`); text, pointers and floats decoded."""
        return await run(ctx, "read_data", what=what, length=length)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def ida(ctx: Context, action: str, query: str = "", count: int = 40) -> str:
        """Ask the project's IDA database directly (read-only; answers are cached).

        Actions:
          xrefs     — references TO and FROM a name or address, with kinds (call, jump, read, write,
                      offset) and the containing functions
          disasm    — raw disassembly at an address, or (given a function name) its whole body in one call
          decompile — Hex-Rays pseudocode for a function, on demand
          types     — IDA's own type library: search a name or prefix, get declaration text
          globals   — named data with their types (filter by name fragment)
          strings   — live string search (filter by fragment; empty = first N)
          segments  — section layout with permissions
        """
        return await run(ctx, "ida", action=action, query=query, count=count)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def set_mode(ctx: Context, function: str, mode: str, note: str = "") -> str:
        """Choose a function's mode: `decompile` (body is a target), `header` (signature/class only;
        never claimed, no body saved) or `skip` (ignored). Matched functions cannot be hidden this
        way. Setting header/skip drops a live claim; the agent may still edit the class/method with
        edit_type or the project-global opaque prelude with declare_opaque.

        Args:
            function: exact name, e.g. "ACME::Aurora::Core::Clock::now()"
            mode: decompile | header | skip
            note: why (stored for the next agent)
        """
        return await run(ctx, "set_mode", function=function, mode=mode, note=note)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def list_functions(ctx: Context, status: str = "open", limit: int = 40, query: str = "") -> str:
        """List functions by status — and search them by name fragment or address.

        Args:
            status: open | working | matched | library | all
            limit: max rows
            query: optional name fragment (e.g. "pushFront") or a 0x address: finds functions
                wherever they are instead of scrolling the list
        """
        return await run(ctx, "list_functions", status=status, limit=limit, query=query)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def add_note(ctx: Context, text: str, function: str = "") -> str:
        """Leave a note for other agents, on a function or the whole project."""
        return await run(ctx, "add_note", text=text, function=function)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def search_notes(ctx: Context, query: str) -> str:
        """Search notes left by agents."""
        return await run(ctx, "search_notes", query=query)

    @mcp.tool(meta=ALWAYS_LOAD)
    async def guide(ctx: Context, topic: str = "") -> str:
        """Decompilation know-how (workflow, x86, aarch64, cpp, data, structs, naming, similarity): call
        without a topic for the list."""
        return await run(ctx, "guide", topic=topic)

    @mcp.prompt(title="Decompile", description="Work loop: claim functions and match them byte for byte.")
    def work(count: str = "5") -> str:
        return "Call project_info first, then follow the decomp.wtf work loop for up to " + count + " functions."

    return mcp
