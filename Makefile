all: arpspf sniffa dpi

arpspf: arpspf.cpp
	g++ arpspf.cpp -Iinc -o debug/arpspf

dpi: dpi.cpp
	g++ dpi.cpp -Iinc -o debug/dpi

sniffa: sniffa.cpp
	g++ sniffa.cpp -Iinc -o debug/sniffa

clean:
	rm -f debug/arpspf
