#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "random_WNG4.h"
#include "sm3.h"
#include "sms4.h"

#define KEYLEN 16

#define DEBUG 0
#if DEBUG
#define D(...) printf(__VA_ARGS__)
#else
#define D(...) ((void)0)
#endif

int create_cipher_file(const char *file_path,
                        const char *plaintext,
                        unsigned int size,
                        const unsigned char *key)
{
    uint32_t  round_key[32];
    FILE* fp = NULL;
    int left;


#if DEBUG
    int i;
    D("round key:\n");
    for (i = 0; i < 32; i++) {
        D("%08x ",round_key[i]);
    }
    D("\n");

    D("plain text: %s\n", plaintext);
    for (i = 0; i < size; i+=4) {
        D("%08x ",*((int*)&plaintext[i]));
    }
    D("\n");
#endif

    sms4_calc_round_key(key, round_key);

    left = size;
    while( left >= SMS4_BLOCK_SIZE )
    {
        sms4_encrypt(&plaintext[size - left], round_key);
        left -= SMS4_BLOCK_SIZE;
    }

#if DEBUG
    D("cipher text:\n");
    for (i = 0; i < size; i+=4) {
        D("%08x ",*((int*)&plaintext[i]));
    }
    D("\n");
#endif

    D("create file : %s\n", file_path);
    fp = fopen(file_path, "w");
    fwrite(plaintext, 1, size, fp);
    fclose(fp);

    return 0;
}

int main(void)
{
    //The "long_text" length must be carried out in integral multiple of 16bytes
    char *long_text = "When scientists look to the stars, they wonder about "
                       "their mystery. When we engineers look to the stars, "
                       "we think about building something to reach them. "
                       "To the stars and for engineering!!!!!!";

    unsigned char tmp_key[32] = {0};
    char *start_key = "12345678";
    char *plain = NULL;
    int i;

    sm3(start_key, strlen(start_key), tmp_key);

    //Create the main key ciphertext

    plain = (char *)realloc(plain, KEYLEN);

    enable_WNG4();
    for (i = 0; i < KEYLEN; i++)
        plain[i] = get_byte_random();
    disable_WNG4();

    create_cipher_file("/mnt/cipher1", plain, KEYLEN, tmp_key);

    //Create the long text ciphertext
    plain = (char *)realloc(plain, strlen(long_text));
    memcpy(plain, long_text, strlen(long_text));
    create_cipher_file("/mnt/cipher2", plain, strlen(long_text), tmp_key);

    free(plain);
    return 0;
}
