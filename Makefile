#
# nomadcap Makefile
#
CC=gcc
CFLAGS=

# Uncomment the following line to include DEBUG code
# CFLAGS=-DEBUG
LDFLAGS=-lpcap
DEPS=nomadcap.h
OBJ=nomadcap.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

nomadcap: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -f *.o
	rm nomadcap

