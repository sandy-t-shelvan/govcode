CXXFLAGS=-std=c++11 -Wall -g -fsanitize=address -fno-omit-frame-pointer

test: test_05
	./test_05

test_05: msgbuf.cpp test_05.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

.PHONY: test
