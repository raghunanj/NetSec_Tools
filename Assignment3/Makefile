all: clean pbproxy

pbproxy: pbproxy.c
	gcc -g pbproxy.c -o pbproxy.o -lssl -lcrypto -lpthread -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include

clean:
	rm -f *~ *.o *.out
