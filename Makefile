CFLAGS=-O2 -ansi -Wall -pedantic

sniffer: sniffer.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f sniffer
