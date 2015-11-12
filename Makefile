all:
	gcc -I . utils/*.c tsocks/local.c -o local

clean:
	rm *.o local
