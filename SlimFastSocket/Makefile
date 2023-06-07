all: SlimFastSocket.c HashTable.c
	gcc -c -g -O3 -Wall -fPIC SlimFastSocket.c HashTable.c 
	gcc -g -shared -o SlimFastSocket.so SlimFastSocket.o  HashTable.o -ldl

clean:
	rm -f *.so *.o
