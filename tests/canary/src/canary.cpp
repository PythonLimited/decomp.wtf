// Synthetic canary for the two first toolchain environments.
//
// The absolute values are unimportant; the shapes are not. Every function is
// noinline and reachable from main so the binary keeps a distinct body for the
// judge to compare. Keep this C++14-compatible: VS2015 U3 is one of the targets.

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <vector>

#if defined(_MSC_VER)
#define CANARY_NOINLINE __declspec(noinline)
#else
#define CANARY_NOINLINE __attribute__((noinline))
#endif

namespace ACME {
namespace Aurora {

CANARY_NOINLINE std::int32_t add(std::int32_t a, std::int32_t b) {
    return a + b;
}

struct Widget {
    std::int32_t value;

    explicit Widget(std::int32_t value_) : value(value_) {}

    CANARY_NOINLINE std::int32_t get() const { return value; }
    CANARY_NOINLINE void set(std::int32_t next) { value = next; }
};

struct Flags {
    unsigned int low : 3;
    unsigned int high : 5;
    unsigned int wide : 8;
};

CANARY_NOINLINE std::uint32_t flags_value(const Flags& flags) {
    return static_cast<std::uint32_t>(flags.low)
        | (static_cast<std::uint32_t>(flags.high) << 3)
        | (static_cast<std::uint32_t>(flags.wide) << 8);
}

class VirtualBase {
public:
    virtual ~VirtualBase() {}
    CANARY_NOINLINE virtual std::int32_t value() const { return 1; }
};

class Derived : public VirtualBase {
public:
    CANARY_NOINLINE std::int32_t value() const override { return 2; }
};

CANARY_NOINLINE std::int32_t call_virtual(const VirtualBase& base) {
    return base.value();
}

CANARY_NOINLINE bool is_derived(const VirtualBase& base) {
    return dynamic_cast<const Derived*>(&base) != 0;
}

std::int32_t global_counter = 0;

CANARY_NOINLINE std::int32_t bump_counter(std::int32_t by) {
    global_counter += by;
    return global_counter;
}

CANARY_NOINLINE std::int32_t read_counter() {
    return global_counter;
}

CANARY_NOINLINE std::int32_t sum_vector(const std::vector<std::int32_t>& values) {
    std::int32_t total = 0;
    for (std::size_t i = 0; i < values.size(); ++i) {
        total += values[i];
    }
    return total;
}

CANARY_NOINLINE std::int32_t string_length(const std::string& value) {
    return static_cast<std::int32_t>(value.size());
}

CANARY_NOINLINE std::int32_t throw_if_negative(std::int32_t value) {
    if (value < 0) {
        throw std::runtime_error("negative");
    }
    return value;
}

CANARY_NOINLINE std::int32_t catch_negative(std::int32_t value) {
    try {
        return throw_if_negative(value);
    } catch (const std::runtime_error&) {
        return -1;
    }
}

template <typename T>
CANARY_NOINLINE T max_value(T a, T b) {
    return a < b ? b : a;
}

CANARY_NOINLINE std::int32_t sum_variadic(std::int32_t count, ...) {
    std::va_list args;
    va_start(args, count);
    std::int32_t total = 0;
    for (std::int32_t i = 0; i < count; ++i) {
        total += va_arg(args, std::int32_t);
    }
    va_end(args);
    return total;
}

CANARY_NOINLINE float mix_float(float a, double b) {
    return static_cast<float>(a + b);
}

CANARY_NOINLINE double mix_double(double a, float b) {
    return a + static_cast<double>(b);
}

}  // namespace Aurora
}  // namespace ACME

int main(int argc, char** argv) {
    const int seed = argc + (argv != 0 ? 1 : 0);

    ACME::Aurora::Widget widget(seed);
    widget.set(widget.get() + 2);

    ACME::Aurora::Flags flags = {1u, 2u, 3u};
    ACME::Aurora::Derived derived;

    std::vector<std::int32_t> values;
    values.push_back(widget.get());
    values.push_back(seed);

    std::string text("acme");

    int result = 0;
    result += ACME::Aurora::add(seed, 3);
    result += widget.get();
    result += static_cast<int>(ACME::Aurora::flags_value(flags));
    result += ACME::Aurora::call_virtual(derived);
    result += ACME::Aurora::is_derived(derived) ? 1 : 0;
    result += ACME::Aurora::bump_counter(seed);
    result += ACME::Aurora::read_counter();
    result += ACME::Aurora::sum_vector(values);
    result += ACME::Aurora::string_length(text);
    result += ACME::Aurora::catch_negative(seed - 4);
    result += ACME::Aurora::max_value<int>(seed, 7);
    result += static_cast<int>(ACME::Aurora::max_value<double>(1.5, 2.5));
    result += ACME::Aurora::sum_variadic(3, seed, 2, 3);
    result += static_cast<int>(ACME::Aurora::mix_float(1.0f, 2.0));
    result += static_cast<int>(ACME::Aurora::mix_double(3.0, 4.0f));

    volatile int sink = result;
    (void)sink;
    return 0;
}
