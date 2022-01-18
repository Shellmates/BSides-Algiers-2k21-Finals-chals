#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define MAX_NOTES      64
#define MAX_NOTE_SIZE  256

typedef unsigned int uint;

char *notes[MAX_NOTES];

void disable_buffering() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void menu() {
	printf(
		"[1] Create\n"
		"[2] Show\n"
		"[3] Delete\n"
		"[0] Quit\n"
		">>> "
	);
}

uint read_int() {
	char tmp[16];
	fgets(tmp, sizeof(tmp), stdin);
	return (uint)atoi(tmp);
}

void create_note() {
	char *content;
	uint i, size;

	printf("Index: ");
	i = read_int();
	if (i > MAX_NOTES) {
		puts("Index out of bounds.");
		return;
	}

	printf("Size: ");
	size = read_int();
	if (size > MAX_NOTE_SIZE) {
		puts("Too big.");
		return;
	}

	printf("Content: ");
	notes[i] = (char *)malloc(size + 1);
	fgets(notes[i], size, stdin);
}

void show_note() {
	uint i;

	printf("Index: ");
	i = read_int();
	if (i > MAX_NOTES) {
		puts("Index out of bounds.");
		return;
	}

	if (notes[i] != NULL) puts(notes[i]);
}

void delete_note() {
	uint i;

	printf("Index: ");
	i = read_int();
	if (i > MAX_NOTES) {
		puts("Index out of bounds.");
		return;
	}

	if (notes[i] != NULL) free(notes[i]);
}

int main(void) {
	disable_buffering();
	for (;;) {
		menu();
		switch (read_int()) {
			case 1:
				create_note();
				break;
			case 2:
				show_note();
				break;
			case 3:
				delete_note();
				break;
			case 0:
				exit(0);
			default:
				puts("No such option.");
				break;
		}

	}
	return 0;
}