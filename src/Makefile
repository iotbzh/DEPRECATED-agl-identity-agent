.PHONY: test

CFLAGS += -g
#CFLAGS += -Wunused-variable

test: ba
	./ba || :

ba: u2f-bluez.c main.c u2f-bluez.h u2f-protocol.c u2f-protocol.h u2f.h
	$(CC) $(CFLAGS) -o ba -g -lsystemd u2f-bluez.c main.c u2f-protocol.c

