#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>

#define SIZE 0x10
#define MAX_ALLOC_SIZE 0x500

void disable_buffering(void);
void read_str(char *msg, char *buf, unsigned int size);
unsigned long read_num(char *msg);
void error(char *str);
void menu(void);
unsigned long find_empty_chunk(void);
void safefree(void **pp);
void alloc(void); 
void delete(void); 
void safedelete(void); 
void view(void); 

bool used = false;
char* chunks[SIZE] = {NULL};

void menu(void) {
	puts("1) Allocate");
	puts("2) Free");
	puts("3) Safefree [FREE TRIAL VERSION]");
	puts("4) View");
	puts("0) Exit");
}

unsigned long find_empty_chunk(void) {
	for(unsigned long i = 0; i < SIZE; i++)
		if(chunks[i] == NULL)
			return i;

	error("No more chunks available.");
	return 0;
}

void safefree(void **pp) {
	assert(pp);
	free(*pp);
	*pp = NULL;
}

void alloc(void) {
	unsigned int idx = find_empty_chunk();
	unsigned long size = read_num("Size: ");
	assert(size <= MAX_ALLOC_SIZE);

	chunks[idx] = (char*)malloc(size);
	assert(chunks[idx] != NULL);
	read_str("Data: ", chunks[idx], size);
}

void delete(void) {
	unsigned long idx = read_num("Index: ");
	assert(idx <= SIZE);
	assert(chunks[idx] != NULL);

	free(chunks[idx]);
	chunks[idx] = NULL;
}

void safedelete(void) {
	if (used) {
		error("Free trial has expired, buy this feature for 1 million Bobux");
	}

	unsigned long idx = read_num("Index: ");
	assert(idx <= SIZE);
	assert(chunks[idx] != NULL);

	safefree((void**)chunks[idx]);
	used = true;
}

void view(void) {
	unsigned long idx = read_num("Index: ");
	assert(idx <= SIZE);
	assert(chunks[idx] != NULL);

	printf("Data: %s\n", chunks[idx]);
}

int main(int argc, char *argv[]) {
	disable_buffering();

	while(true) {
		menu();
		switch(read_num("Choice: ")) {
			case 1:
				alloc();
				break;
			case 2:
				delete();
				break;
			case 3:
				safedelete();
				break;
			case 4:
				view();
				break;
			case 0:
				puts("Bye!");
				return EXIT_SUCCESS;
			default:
				error("Invalid option.");
				break;
		}
	}

	return EXIT_SUCCESS;
}

void disable_buffering(void) {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
}

void read_str(char *msg, char *buf, unsigned int size) {
	printf("%s", msg);
	assert(read(STDIN_FILENO, buf, size));
}

unsigned long read_num(char *msg) {
  char buf[24] = {'\0'};

  read_str(msg, buf, 24);
  return (unsigned long)atol(buf);
}

void error(char *str) {
	fprintf(stderr, "%s", str);
	exit(1);
}
