CXXFLAGS=-std=c++17 -Wall -Werror=deprecated-declarations -g

test: no-auto-ptr test_04
	./test_04

test_04: sensor_bus.cpp test_04.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

no-auto-ptr:
	! grep -n auto_ptr sensor_bus.h sensor_bus.cpp

.PHONY: test no-auto-ptr
