CFLAGS=-O2 -std=c99 -Wall -Wextra -pedantic

sniffer: sniffer.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f sniffer
