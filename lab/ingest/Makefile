CXX ?= g++
CXXFLAGS ?= -std=c++20 -O2 -Wall -Wextra -Wpedantic -pthread
BIN := collector_selftest

all: $(BIN)

$(BIN): main.cpp collector.hpp
	$(CXX) $(CXXFLAGS) -o $@ main.cpp

check: $(BIN)
	./$(BIN)

clean:
	rm -f $(BIN)

.PHONY: all check clean
