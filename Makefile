local:
	gcc -I . utils/*.c tsocks/local.c -o local

server:
	gcc -I . utils/*.c tsocks/server.c -o server

clean:
	rm *.o local server client a
