CFLAGS=-std=c89 -Wall -O0 -g

test: test_02
	./test_02

test_02: frame.c test_02.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: test
