all: arpspf.cpp
	g++ arpspf.cpp -Iinc -o debug/arpspf

clean:
	rm -f debug/arpspf
