all:
	gcc -I . utils/*.c tsocks/local.c -o local

test:
	gcc -I . tests/test_list.c -o tests/test_list
clean:
	rm *.o local
