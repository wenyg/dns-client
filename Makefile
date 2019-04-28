all: query

query: dns_client.c dns_client.h example.c
	gcc -o $@ $^ 

clean:
	rm query
