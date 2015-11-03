all:
	gcc utils/log.c tsocks/local.c -o local

clean:
	rm *.o local
