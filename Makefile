all: arpspf sniffa

arpspf: arpspf.cpp
	g++ arpspf.cpp -Iinc -o debug/arpspf

sniffa: sniffa.cpp
	g++ sniffa.cpp -Iinc -o debug/sniffa

clean:
	rm -f debug/arpspf
