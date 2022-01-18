CC=gcc
CFLAGS=-no-pie -fstack-protector
SOURCE=freenote.c
OUTFILE=../challenge/freenote

all: $(SOURCE)
	$(CC) $(SOURCE) $(CFLAGS) -o $(OUTFILE)
clean: $(OUTFILE)
	rm -f $(OUTFILE)
