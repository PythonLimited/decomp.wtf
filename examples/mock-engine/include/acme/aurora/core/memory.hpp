#pragma once

#include <cstddef>

namespace ACME::Aurora::Core {

class Memory {
public:
    static void* DmMalloc(std::size_t size, std::size_t alignment, int flags, const void* hint);
    static void  DmFree(void* ptr);
    static void  DmCheckHeap();
    static void* DmAlignedMalloc(std::size_t size, std::size_t alignment);
    static void  DmAlignedFree(void* ptr);
    static void  DmSetDebugFileName(void* ptr, const char* file, int line);
};

class OSMemory {
public:
    enum Type { TYPE_NORMAL, TYPE_VRAM };

    struct Handle {
        void*       pointer;
        std::size_t size;
    };

    static void   Initialize();
    static void   Terminate();
    static Handle* AllocatePointer(std::size_t size, std::size_t alignment, Type type,
                                   const char* name, Handle* parent, bool zeroed);
    static void   FreePointer(void* pointer);
    static void   Free(Handle* handle);
    static std::size_t GetTotalAllocationSize();
    static void   VirtualRelease(void* pointer, std::size_t size);
};

class DebugMemoryTag {
public:
    static void Push(const char* file, int line);
    static void Pop();
};

}  // namespace ACME::Aurora::Core
