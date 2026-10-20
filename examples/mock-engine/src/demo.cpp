#include "acme/aurora/core/memory.hpp"
#include "acme/obsidian/base/string.hpp"

#include <cstdio>

int main() {
    using ACME::Obsidian::Base::String;
    using ACME::Obsidian::Std::DynamicArray;

    DynamicArray<String, 2, 16> matches;
    const bool found = String::ExtractMatch(matches, "<tag>hello</tag>", "<tag>", "</tag>");

    ACME::Aurora::Core::DebugMemoryTag::Push("demo.cpp", __LINE__);
    auto* handle = ACME::Aurora::Core::OSMemory::AllocatePointer(
        64, 8, ACME::Aurora::Core::OSMemory::TYPE_NORMAL, "demo", nullptr, true);
    ACME::Aurora::Core::DebugMemoryTag::Pop();

    std::printf("match=%d allocated=%d heap=%zu\n", found ? 1 : 0, handle != nullptr ? 1 : 0,
                ACME::Aurora::Core::OSMemory::GetTotalAllocationSize());

    ACME::Aurora::Core::OSMemory::Free(handle);
    return found ? 0 : 1;
}
