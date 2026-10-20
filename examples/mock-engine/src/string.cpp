#include "acme/obsidian/base/string.hpp"

#include <cstring>

namespace ACME::Obsidian::Base {

String::String() : data_(nullptr), length_(0), allocated_(0) {}

String::String(const char* text) : String() {
    if (text != nullptr) {
        length_ = static_cast<unsigned int>(std::strlen(text));
        allocated_ = length_ + 1;
        data_ = new char[allocated_];
        std::memcpy(data_, text, allocated_);
    }
}

String::String(const String& other) : String() {
    if (other.data_ != nullptr) {
        length_ = other.length_;
        allocated_ = other.length_ + 1;
        data_ = new char[allocated_];
        std::memcpy(data_, other.data_, allocated_);
    }
}

String& String::operator=(const String& other) {
    if (this != &other) {
        String copy(other);
        char* old = data_;
        data_ = copy.data_;
        length_ = copy.length_;
        allocated_ = copy.allocated_;
        copy.data_ = old;
        copy.length_ = 0;
        copy.allocated_ = 0;
    }
    return *this;
}

String::~String() { delete[] data_; }

void String::Clear() {
    delete[] data_;
    data_ = nullptr;
    length_ = 0;
    allocated_ = 0;
}

void String::Add(const String& other) {
    const unsigned int total = length_ + other.length_ + 1;
    char* merged = new char[total];
    if (data_ != nullptr) {
        std::memcpy(merged, data_, length_);
    }
    if (other.data_ != nullptr) {
        std::memcpy(merged + length_, other.data_, other.length_);
    }
    merged[total - 1] = '\0';
    delete[] data_;
    data_ = merged;
    length_ = total - 1;
    allocated_ = total;
}

void String::Join(const char*, const char*) {}

bool String::ExtractMatch(Std::DynamicArray<String, 2, 16>& output,
                          const char* text, const char* prefix, const char* suffix) {
    if (text == nullptr || prefix == nullptr || suffix == nullptr) {
        return false;
    }
    const std::size_t text_len = std::strlen(text);
    const std::size_t prefix_len = std::strlen(prefix);
    const std::size_t suffix_len = std::strlen(suffix);
    if (text_len < prefix_len + suffix_len) {
        return false;
    }
    if (std::strncmp(text, prefix, prefix_len) != 0) {
        return false;
    }
    if (std::strcmp(text + text_len - suffix_len, suffix) != 0) {
        return false;
    }
    String inner;
    for (std::size_t i = prefix_len; i < text_len - suffix_len; ++i) {
        const char one[2] = {text[i], '\0'};
        String piece(one);
        inner.Add(piece);
    }
    output.Add(inner);
    return true;
}

}  // namespace ACME::Obsidian::Base
