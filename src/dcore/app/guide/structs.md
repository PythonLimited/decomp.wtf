# Working out structs

Where types live: the project's IDA database (`.i64`) is the database — types the binary's
debug info carries come from it, and your `declare_type` / `edit_type` commits are verified
against the matched functions and then written *into* it (parse into the local type library,
save). IDA shows them too, and a reopened database still knows them. Names and types edited
directly in IDA (by hand or by another tool) flow back the next time the project is analyzed —
the project screen says when the database changed since the last analysis ("Analyze again").

1. Collect every offset used with one base pointer: `lw $v0, 0x1C($a0)`, `sh $a1, 0x22($a0)`, ...
2. The width and signedness of each access gives the field type (lw = 32-bit, lhu = u16, lb = s8, lwc1 =
   f32, ...).
3. Lay fields out in offset order with explicit padding for gaps, and comment the offsets:

```c
typedef struct Actor {
    /* 0x00 */ s16 type;
    /* 0x02 */ u16 flags;
    /* 0x04 */ f32 x;
    /* 0x08 */ char pad08[0x14];
    /* 0x1C */ s32 hp;
} Actor; /* size >= 0x20 */
```

4. Alignment: s16 on 2, s32/f32/pointers on 4, s64/f64 on 8. The compiler pads to this; your struct
   must produce the same offsets.
5. The size shows in array indexing (`mult` by a constant, or `sll` + `addu` sequences for stride) and
   in `sizeof` loops.
6. Put the struct in context.h with `edit_context` once it works, so every agent uses the same one, and
   rename the global with `rename_symbol`. Unknown fields: `unk_1C` style names are fine.
