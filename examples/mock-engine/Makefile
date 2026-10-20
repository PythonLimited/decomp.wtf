CXX ?= c++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Iinclude
AR ?= ar

SRC := src/string.cpp src/memory.cpp
OBJ := $(SRC:.cpp=.o)

.PHONY: all clean run

all: demo

libmockengine.a: $(OBJ)
	$(AR) rcs $@ $^

demo: src/demo.cpp libmockengine.a
	$(CXX) $(CXXFLAGS) -o $@ src/demo.cpp libmockengine.a

run: demo
	./demo

clean:
	rm -f $(OBJ) libmockengine.a demo
