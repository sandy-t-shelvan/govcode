CFLAGS=-std=c89 -Wall -Werror -Isrc
SRCS=src/sensor.c src/monitor.c src/log.c

test: test_10
	./test_10

test_10: $(SRCS) test_10.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: test
