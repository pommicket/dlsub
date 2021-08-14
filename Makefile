dlsub: main.c
	$(CC) -O2 -g -o dlsub main.c -std=c89 -Wpedantic -pedantic -Wall -Wextra -Wshadow -Wconversion -Wimplicit-fallthrough
