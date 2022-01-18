#include <pthread.h>
#include <gcrypt.h>
#include <stdio.h>
#include <errno.h>

// Compile with: gcc challenge.c -o challenge -lgcrypt -lgpg-error -lpthread

#define GCRY_ERR(myerr, myhd) while(1){ perror("gcry error!\n"); printf("%s\n", gpg_strerror(myerr)); gcry_cipher_close(myhd); pthread_exit(NULL); }
#define ALGO GCRY_CIPHER_AES128

#define INPUT_SIZE 256

#define KEY "\x29\xae\xcc\xd2\x02\x85\xee\x3c\x84\x3d\x8d\x4e\xcd\xe6\x79\x84"


char enc[] = { 0xd0, 0xec, 0xe7, 0x77, 0x0c, 0xde, 0xce, 0x84, 0xe3, 0xe7, 0xdc, 0x2c, 0x0a, 0xe3, 0x9d, 0xfb, 0xf0, 0xca, 0xc5, 0x69, 0x07, 0xd9, 0xf2, 0x6f, 0x9e, 0xee, 0x30, 0xe1, 0x51, 0xbb, 0x46, 0xa5, 0xed, 0xc2, 0xb3, 0x24, 0xdf, 0xfd, 0xd8, 0x79, 0x71, 0x0e, 0x0e, 0x00, 0x5d, 0x03, 0x1e, 0x3d, 0x46, 0x52, 0x9c, 0xbf, 0x65, 0xc3, 0x98, 0xfd, 0x5e, 0xa9, 0xa5, 0xf3, 0x48, 0xcc, 0x9c, 0x2e, 0xfe, 0x2d, 0xa2, 0xbb, 0xc1, 0x2c, 0xe3, 0x4a, 0xe4, 0xfd, 0xea, 0x2b, 0xa4, 0xa1, 0xfb, 0x8c };

#define FLAG_NUM_BLOCKS (sizeof(enc)/16)

#define MAX_THREAD_COUNT FLAG_NUM_BLOCKS

struct encryption_dest {
  char* buffer_in;  // where the buffer starts (contains plaintext initially, will also receive the ciphertext)
  char* buffer_out;
  unsigned int thread_index; // the initial ctr value of the thread
} encryption_dest;

unsigned long num_threads;

pthread_t threads[MAX_THREAD_COUNT];

void uint2block(char* out, uint val, int blklen)
{
  memset(out, 0, blklen);
  *(uint*)out = val;
  for (unsigned int i = 0; i < blklen/2; i++)
  {
    char temp = out[i];
    out[i] = out[blklen-i-1];
    out[blklen-i-1] = temp;
  }
}

void* encrypt_block(void* encryption_dest_structure)
{
  struct encryption_dest* out = (struct encryption_dest*) encryption_dest_structure;

  gcry_cipher_hd_t hd;
  gcry_error_t err = 0;
  err |= gcry_cipher_open(&hd, ALGO, GCRY_CIPHER_MODE_CTR, 0);

  if (err) GCRY_ERR(err, hd)

  int keylen = gcry_cipher_get_algo_keylen(ALGO);
  int blklen = gcry_cipher_get_algo_blklen(ALGO);

  char* ctr = malloc(blklen);
  if (ctr == NULL)
  {
    perror("[-] Malloc error");
    pthread_exit(NULL);
  }
  // convert the integer out.ctr_index into a block

  unsigned int ctr_index = out->thread_index;

  uint2block(ctr, ctr_index, blklen);

  err |= gcry_cipher_setkey(hd, KEY, keylen);

  if (err) GCRY_ERR(err, hd)

  err |= gcry_cipher_setctr(hd, ctr, blklen);

  if (err) GCRY_ERR(err, hd)


  err |= gcry_cipher_decrypt(hd, out->buffer_out+out->thread_index*blklen, blklen, out->buffer_in+out->thread_index*blklen, blklen);

  if (err) GCRY_ERR(err, hd)

  // success

  free(ctr);
  gcry_cipher_close(hd);

  int res = memcmp(out->buffer_out+out->thread_index*blklen, enc+out->thread_index*blklen, blklen);
  free(out);

  pthread_exit((void*) res);
}

void read_input(char* inp, ssize_t len)
{
  fgets(inp, len, stdin);
}

unsigned long read_uint(unsigned long default_value)
{
  char buf[16];
  read_input(buf, sizeof(buf));
  errno = 0;
  unsigned long res = strtoul(buf, NULL, 10);
  return ((errno || !res) ? default_value : res);
}

char run_and_check_input(char* input, char* output)
{
  for (unsigned int i = 0; i < num_threads; i++)
  {
    struct encryption_dest* dest = malloc(sizeof(struct encryption_dest));
    if (dest == NULL)
    {
      perror("[-] Malloc error\n");
      exit(1);
    }
    dest->buffer_in = input;
    dest->buffer_out = output;
    dest->thread_index = i;
    pthread_create(&threads[i], NULL, encrypt_block, (void*) dest);
  }
  int res;
  for (unsigned int i = 0; i < num_threads; i++)
  {
    void* retval;
    pthread_join(threads[i], &retval);
    res |= (int) retval;
  }

  // decrypted successfully, and with enough threads
  return (res == 0 && num_threads == sizeof(enc)/16);
}

int main(int argc, char* argv[])
{
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  (void)gcry_check_version(NULL);

  puts("Number of threads >> ");
  num_threads = read_uint(1UL);

  printf("num_threads = %ul\n", num_threads);
  if (num_threads > sizeof(threads))
  {
    perror("You can't have more threads than ciphertext blocks, exiting!");
    exit(1);
  }

  char output[sizeof(enc)] = {0}; // the encryption result, the same size as the encrypted flag
  char input[INPUT_SIZE] = {0}; // the user input

  puts("Please enter the flag >> ");
  read_input(input, sizeof(input));

  // decrypted successfully, and with enough threads
  if (run_and_check_input(input, output))
    puts("[+] Success, you found the right input, congrats! That's it for the reverse-engineering part");
  else
    puts("[-] Wrong input");
  return 0;
}
