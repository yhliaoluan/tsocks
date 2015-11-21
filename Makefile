local:
	gcc -I . utils/*.c tsocks/local.c -o local -levent

server:
	gcc -I . utils/*.c tsocks/server.c -o server -levent

clean:
	rm *.o local server client a
