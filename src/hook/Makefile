CC = gcc
C_BASE_FLAGS = -Wall -shared -fPIC -ldl -I.
C_PROD_FLAGS = -s -O3
C_DEBUG_FLAGS = -g -DDEBUG

all:
	$(CC) $(C_BASE_FLAGS) $(C_PROD_FLAGS) hook.c -o hook.so

debug:
	$(CC) $(C_BASE_FLAGS) $(C_DEBUG_FLAGS) hook.c -o hook.so

clean:
	rm -f hook.so
