CXXFLAGS=-std=c++17 -Wall -Werror=deprecated-declarations -g

test: test_04
	./test_04

test_04: sensor_bus.cpp test_04.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

.PHONY: test
