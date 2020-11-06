CFLAGS=-O2 -std=c99 -Werror=vla -Wall -pedantic

sniffer: sniffer.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f sniffer
