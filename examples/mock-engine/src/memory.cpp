#include "acme/aurora/core/memory.hpp"

#include <cstdlib>

namespace ACME::Aurora::Core {

void* Memory::DmMalloc(std::size_t size, std::size_t, int, const void*) {
    return std::malloc(size);
}

void Memory::DmFree(void* ptr) { std::free(ptr); }

void Memory::DmCheckHeap() {}

void* Memory::DmAlignedMalloc(std::size_t size, std::size_t) {
    return std::malloc(size);
}

void Memory::DmAlignedFree(void* ptr) { std::free(ptr); }

void Memory::DmSetDebugFileName(void*, const char*, int) {}

void OSMemory::Initialize() {}
void OSMemory::Terminate() {}

OSMemory::Handle* OSMemory::AllocatePointer(std::size_t size, std::size_t, Type,
                                            const char*, Handle*, bool) {
    auto* handle = static_cast<Handle*>(std::malloc(sizeof(Handle)));
    if (handle != nullptr) {
        handle->pointer = std::malloc(size);
        handle->size = size;
    }
    return handle;
}

void OSMemory::FreePointer(void* pointer) { std::free(pointer); }

void OSMemory::Free(Handle* handle) {
    if (handle != nullptr) {
        std::free(handle->pointer);
        std::free(handle);
    }
}

std::size_t OSMemory::GetTotalAllocationSize() { return 0; }

void OSMemory::VirtualRelease(void* pointer, std::size_t) { std::free(pointer); }

void DebugMemoryTag::Push(const char*, int) {}
void DebugMemoryTag::Pop() {}

}  // namespace ACME::Aurora::Core
