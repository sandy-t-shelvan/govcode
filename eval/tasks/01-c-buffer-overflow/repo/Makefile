CFLAGS=-std=c89 -Wall -O0 -g

test: test_01
	./test_01

test_01: track.c test_01.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: test
