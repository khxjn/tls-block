all: tls-block

tls-block: main.o tls-block.o tls-parser.o
	g++ -o tls-block main.o tls-block.o tls-parser.o -lpcap

main.o: main.cpp tls-block.h tls-parser.h struct_hdr.h
	g++ -c -o main.o main.cpp

tls-block.o: tls-block.cpp tls-block.h struct_hdr.h
	g++ -c -o tls-block.o tls-block.cpp

tls-parser.o: tls-parser.cpp tls-parser.h tls-block.h struct_hdr.h
	g++ -c -o tls-parser.o tls-parser.cpp

clean:
	rm -f tls-block
	rm -f *.o