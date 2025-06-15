all: main.cpp
	g++ main.cpp -o debug/a.out

clean:
	rm -f debug/a.out
