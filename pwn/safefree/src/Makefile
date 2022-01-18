CC=gcc
CFLAGS=-Wl,-z,relro,-z,now -fstack-protector
SOURCE=safefree.c
OUTFILE=../challenge/safefree

all: $(SOURCE)
	$(CC) $(SOURCE) $(CFLAGS) -o $(OUTFILE)
clean: $(OUTFILE)
	rm -f $(OUTFILE)
