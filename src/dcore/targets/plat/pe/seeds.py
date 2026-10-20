"""Pure-Python PE seed inventory: `.pdata`, imports, exports, TLS, load config.

This replaces the optional native loader for the analysis-only seed fields.  It deliberately
reads only the tables the analysis uses; the full `NativeImage` parse remains in `image.py`.
"""

from __future__ import annotations

import struct

from ...image import _u16, _u32, _u64

PE32 = 0x10B
PE32_PLUS = 0x20B
MACHINE_X86_64 = 0x8664


class _Headers:
    def __init__(self, data: bytes):
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ValueError("not a PE")
        pe_off = _u32(data, 0x3C)
        if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\0\0":
            raise ValueError("bad PE signature")
        self.data = data
        self.machine = _u16(data, pe_off + 4)
        nsec = _u16(data, pe_off + 6)
        size_opt = _u16(data, pe_off + 20)
        opt = pe_off + 24
        if opt + size_opt > len(data):
            raise ValueError("truncated optional header")
        magic = _u16(data, opt)
        if magic == PE32_PLUS:
            self.bits = 64
            self.image_base = _u64(data, opt + 24)
            self.dd = opt + 112
        elif magic == PE32:
            self.bits = 32
            self.image_base = _u32(data, opt + 28)
            self.dd = opt + 96
        else:
            raise ValueError("unknown optional header")
        self.sections: list[tuple[int, int, int, int]] = []
        for i in range(nsec):
            o = opt + size_opt + 40 * i
            if o + 40 > len(data):
                break
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
            if vsize or rawsize:
                self.sections.append((vaddr, vsize, rawptr, rawsize))
        self.data_dirs = []
        for i in range(16):
            o = self.dd + 8 * i
            self.data_dirs.append(struct.unpack_from("<II", data, o) if o + 8 <= len(data)
                                  else (0, 0))

    def rva(self, value: int) -> int | None:
        if not value:
            return None
        for vaddr, vsize, rawptr, rawsize in self.sections:
            if vaddr <= value < vaddr + max(vsize, rawsize):
                delta = value - vaddr
                return rawptr + delta if delta < rawsize else None
        return None

    def directory(self, index: int) -> tuple[int, int]:
        return self.data_dirs[index] if index < len(self.data_dirs) else (0, 0)

    def cstring(self, rva: int, limit: int = 512) -> str:
        off = self.rva(rva)
        if off is None:
            return ""
        end = self.data.find(b"\0", off, min(len(self.data), off + limit))
        if end < 0:
            end = min(len(self.data), off + limit)
        return self.data[off:end].decode("ascii", "replace")


def _thunk_count(h: _Headers, rva: int) -> int:
    off = h.rva(rva)
    if off is None:
        return 0
    width = 8 if h.bits == 64 else 4
    count = 0
    for i in range(100000):
        if off + width > len(h.data):
            break
        value = _u64(h.data, off) if width == 8 else _u32(h.data, off)
        if not value:
            break
        count += 1
        off += width
    return count


def _imports(h: _Headers) -> tuple[int, int]:
    rva, size = h.directory(1)
    off = h.rva(rva) if rva else None
    if off is None or not size:
        return 0, 0
    dlls = functions = 0
    for i in range(100000):
        at = off + i * 20
        if at + 20 > len(h.data):
            break
        original, _stamp, _chain, name_rva, first = struct.unpack_from("<IIIII", h.data, at)
        if not (original or name_rva or first):
            break
        name = h.cstring(name_rva)
        if not name:
            continue
        dlls += 1
        functions += _thunk_count(h, original or first)
    return dlls, functions


def _delay_imports(h: _Headers) -> int:
    rva, size = h.directory(13)
    off = h.rva(rva) if rva else None
    if off is None or not size:
        return 0
    dlls = 0
    for i in range(10000):
        at = off + i * 32
        if at + 32 > len(h.data):
            break
        attrs, name_rva, _hmod, _iat, int_rva = struct.unpack_from("<IIIII", h.data, at)
        if not name_rva:
            break
        # Old-style descriptors store VAs; modern MSVC stores RVAs (grAttrs bit 0).
        if not (attrs & 1):
            if name_rva >= h.image_base:
                name_rva -= h.image_base
            if int_rva >= h.image_base:
                int_rva -= h.image_base
        if h.cstring(name_rva):
            dlls += 1
    return dlls


def _exports(h: _Headers) -> int:
    rva, _size = h.directory(0)
    off = h.rva(rva) if rva else None
    if off is None or off + 40 > len(h.data):
        return 0
    return _u32(h.data, off + 20)  # NumberOfFunctions


def _tls_callbacks(h: _Headers) -> list[int]:
    rva, _size = h.directory(9)
    off = h.rva(rva) if rva else None
    if off is None:
        return []
    width = 8 if h.bits == 64 else 4
    callbacks_va = (_u64(h.data, off + 24) if width == 8 else _u32(h.data, off + 12))
    if not callbacks_va:
        return []
    callbacks_rva = callbacks_va - h.image_base if callbacks_va >= h.image_base else callbacks_va
    at = h.rva(callbacks_rva)
    if at is None:
        return []
    out = []
    for _ in range(4096):
        if at + width > len(h.data):
            break
        value = _u64(h.data, at) if width == 8 else _u32(h.data, at)
        if not value:
            break
        out.append(value)
        at += width
    return out


def _load_config(h: _Headers) -> tuple[int, int]:
    rva, size = h.directory(10)
    off = h.rva(rva) if rva else None
    if off is None or not size:
        return 0, 0
    declared = _u32(h.data, off) or size
    limit = min(len(h.data), off + declared)
    cookie_at, check_at = (88, 112) if h.bits == 64 else (60, 72)
    width = 8 if h.bits == 64 else 4
    cookie = _u64(h.data, off + cookie_at) if width == 8 else _u32(h.data, off + cookie_at)
    check = _u64(h.data, off + check_at) if width == 8 else _u32(h.data, off + check_at)
    if off + cookie_at + width > limit:
        cookie = 0
    if off + check_at + width > limit:
        check = 0
    return check, cookie


def parse(data: bytes) -> dict | None:
    """The PE seed tables, or None when the file is not a parseable PE."""
    try:
        h = _Headers(data)
        pdata: list[tuple[int, int, int]] = []
        if h.machine == MACHINE_X86_64 and h.bits == 64:
            rva, size = h.directory(3)
            off = h.rva(rva) if rva else None
            if off is not None:
                for i in range(min(size // 12, 1000000)):
                    at = off + i * 12
                    if at + 12 > len(data):
                        break
                    begin, end, unwind = struct.unpack_from("<III", data, at)
                    if not begin:
                        continue
                    pdata.append((h.image_base + begin, h.image_base + end,
                                  h.image_base + unwind))
        import_dlls, imports = _imports(h)
        cfg_check, security_cookie = _load_config(h)
        return {
            "pdata": pdata,
            "import_dlls": import_dlls,
            "imports": imports,
            "delay_dlls": _delay_imports(h),
            "exports": _exports(h),
            "tls_callbacks": _tls_callbacks(h),
            "cfg_check": cfg_check,
            "security_cookie": security_cookie,
        }
    except Exception:
        return None
