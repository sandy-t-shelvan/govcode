CFLAGS=-std=c89 -Wall -Werror -Isrc
SRCS=src/sensor.c src/monitor.c src/log.c

test: no-old-name test_10
	./test_10

test_10: $(SRCS) test_10.c
	$(CC) $(CFLAGS) -o $@ $^

no-old-name:
	! grep -rn getTemp src test_10.c

.PHONY: test no-old-name
