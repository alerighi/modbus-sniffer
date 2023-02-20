#CFLAGS=-O2 -std=c99 -Wall -Wextra -pedantic
CXXFLAGS=-O2 -std=c++11 -Wall -Wextra -pedantic

sniffer: sniffer.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f sniffer
