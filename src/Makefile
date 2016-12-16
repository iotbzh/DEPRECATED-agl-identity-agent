.PHONY: test

CFLAGS += -g
#CFLAGS += -Wunused-variable

test: ba
	./ba || :

ba: u2f-bluez.c main.c u2f-bluez.h u2f-protocol.c u2f-protocol.h u2f.h u2f-bt.c u2f-bt.h u2f-crypto.c u2f-crypto.h
	$(CC) $(CFLAGS) -o ba -g -lsystemd -lcrypto u2f-bluez.c main.c u2f-protocol.c u2f-bt.c u2f-crypto.c

