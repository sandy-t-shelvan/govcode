CFLAGS=-std=c89 -Wall -O0 -g

test: test_03
	./test_03

test_03: crc.c test_03.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: test
