#pragma once

#include <cstddef>

namespace ACME::Obsidian::Base {

class Allocatable {};

class String;

}  // namespace ACME::Obsidian::Base

namespace ACME::Obsidian::Std {

template <typename T, int N0, typename T1, int N1>
struct SmallPointer;

template <typename T, int N0, int N1>
class DynamicArray;

}  // namespace ACME::Obsidian::Std

namespace ACME::Obsidian::Base {

class String : public Allocatable {
public:
    String();
    explicit String(const char* text);
    String(const String& other);
    String& operator=(const String& other);
    ~String();

    void Clear();
    void Add(const String& other);
    void Join(const char* separator, const char* suffix);

    static bool ExtractMatch(Std::DynamicArray<String, 2, 16>& output,
                             const char* text, const char* prefix, const char* suffix);

private:
    char*        data_;
    unsigned int length_;
    unsigned int allocated_;
};

}  // namespace ACME::Obsidian::Base

namespace ACME::Obsidian::Std {

template <typename T, int N0, typename T1, int N1>
struct SmallPointer {
    T* data;
};

template <typename T, int N0, int N1>
class DynamicArray {
public:
    DynamicArray() : data_{values_}, size_(0), reservedSize_(N1) {}

    void Clear() { size_ = 0; }
    void Add(const T& value) {
        if (size_ < N1) {
            values_[size_++] = value;
        }
    }
    void Join(const char*, const char*) {}

private:
    T                            values_[N1 > 0 ? N1 : 1];
    SmallPointer<T, 0, unsigned int, 32> data_;
    unsigned int                 size_;
    unsigned int                 reservedSize_;
};

}  // namespace ACME::Obsidian::Std
