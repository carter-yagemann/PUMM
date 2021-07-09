CC = gcc
C_BASE_FLAGS = -Wall -shared -fPIC -I. -Wl,--no-as-needed -ldl
C_PROD_FLAGS = -s -O3
C_DEBUG_FLAGS = -g -DDEBUG

all:
	$(CC) $(C_BASE_FLAGS) $(C_PROD_FLAGS) hook.c -o hook.so
	$(CC) $(C_BASE_FLAGS) $(C_DEBUG_FLAGS) hook.c -o hook-debug.so
	$(CC) $(C_BASE_FLAGS) $(C_PROD_FLAGS) -DSCAN hook.c -o hook-scan.so

clean:
	rm -f *.so
