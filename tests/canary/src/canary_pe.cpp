// Minimal freestanding PE canary: no CRT, STL, exceptions or RTTI.
// It lets the VS2015 image produce a real PE for environment/judge tests even
// though the image intentionally carries headers and cl only, not link libraries.

#if defined(_MSC_VER)
#define CANARY_NOINLINE __declspec(noinline)
#else
#define CANARY_NOINLINE __attribute__((noinline))
#endif

extern "C" CANARY_NOINLINE int canary_add(int a, int b) {
    return a + b;
}

struct Widget {
    int value;
    CANARY_NOINLINE int get() const { return value; }
    CANARY_NOINLINE void set(int next) { value = next; }
};

CANARY_NOINLINE int canary_widget(int seed) {
    Widget widget;
    widget.value = seed;
    widget.set(widget.get() + 2);
    return widget.value;
}

struct Flags {
    unsigned int low : 3;
    unsigned int high : 5;
};

CANARY_NOINLINE unsigned int canary_flags(const Flags& flags) {
    return flags.low | (flags.high << 3);
}

int canary_global = 0;

CANARY_NOINLINE int canary_bump(int by) {
    canary_global += by;
    return canary_global;
}

int main(int argc, char** argv) {
    Flags flags = {1u, 2u};
    int result = canary_add(argc, 3);
    result += canary_widget(argc);
    result += static_cast<int>(canary_flags(flags));
    result += canary_bump(argc);
    return result == 0 ? 1 : 0;
}
