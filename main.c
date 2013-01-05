/* ruuveal - Decrypt HTC encrypted RUUs (rom.zip files).
 *
 * Copyright (C) 2013 Kenny Millington
 * 
 */
//#define DEBUG_ENABLED

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "htcaes.h"
#include "htckey.h"

#ifdef DEBUG_ENABLED
#define DEBUG(x) x
#else
#define DEBUG(x)
#endif

#define FAIL(x) rc = x; goto end;

#define HTC_ZIPAES_HDR "Htc@egi$"

#ifdef DEBUG_ENABLED
static void debug(const char *fmt, ...)
{
    static int prefix = 0;
    va_list args;
    if(prefix == 0) {
        fprintf(stderr, "debug> ");
        prefix = 1;
    }

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    if(strstr(fmt, "\n")) {
        prefix = 0;
    }
}

static void dump(const char *label, const unsigned char *data, int len)
{
    int i;

    debug("%s dump (offset: 0x%08lx, size: %d):-\n",
          label, (unsigned long int)data, len);

    for(i = 0; i < len; i++) {
        debug("%02x ", (unsigned char)data[i]);
        if((i + 1) % 16 == 0)
            debug("\n", i);
    }

    debug("\n");
}
#endif

int usage(const char **argv)
{
    int i;
    printf("usage:-\n\n");
    printf("%s <device> <encrypted.zip> <decrypted.zip>\n\n", argv[0]);
    
    /* FIXME: Generate this list automatically. */
    printf("supported devices:-\n\n");
    printf("evita\t\t- HTC One X (S4)\n");    
    printf("fireball\t- HTC Incredible 4G\n");
    printf("jewel\t\t- HTC EVO 4G LTE)\n");
    printf("ville\t\t- HTC One S\n\n");

    return -1;
}

void progress_update(unsigned int pos, unsigned int size) 
{
    printf("Decrypting RUU... %d/%d\r", pos, size);
}

int main(int argc, const char **argv)
{
    char key[HTC_AES_KEYSIZE] = {0};
    char iv[HTC_AES_KEYSIZE] = {0};
    int rc = 0;

    unsigned short keymap_index = 0;
    unsigned int chunk_size = 0;

    FILE *in = NULL, *out = NULL;

    if(argc != 4) {
        return usage(argv);
    }
    
    printf("ruuveal - ALPHA BUILD\n");
    printf("A HTC RUU decrypter\n");
    printf("---------------------\n\n");

    /* Open the encrypted.zip file. */
    if((in = fopen(argv[2], "rb")) == NULL) {
        perror("failed to open encrypted zip");
        FAIL(-2)
    }
    
    /* Validate zip file is a HTC AES encrypted zip file. */
    fread(key, sizeof(char), strlen(HTC_ZIPAES_HDR), in);
    if(strncmp(key, HTC_ZIPAES_HDR, strlen(HTC_ZIPAES_HDR))) {
        fseek(in, 0x100, SEEK_SET);
        fread(key, sizeof(char), strlen(HTC_ZIPAES_HDR), in);
        if(strncmp(key, HTC_ZIPAES_HDR, strlen(HTC_ZIPAES_HDR))) {
            fprintf(stderr, "invalid htc aes encrypted zipfile\n");
            FAIL(-4)
        }
    }
    
    /* Read the keymap index. */
    fread((void *)&keymap_index, sizeof(unsigned short), 1, in);
    keymap_index = (keymap_index>>8) | (keymap_index & 0xFF);
    
    /* Read the chunk size. */
    fread(key, sizeof(char), 1, in);
    chunk_size = key[0]<<20;

    /* Advance to real start of zip file. */
    fseek(in, 0x80 - (strlen(HTC_ZIPAES_HDR) + 2 + 1), SEEK_CUR);
    
    /* Generate AES/IV for decryption. */
    if(htc_generate_aes_keys(argv[1], keymap_index, key, iv) == 0) {
        fprintf(stderr, "failed to generate htc aes keys\n");
        FAIL(-5)
    }

    DEBUG(dump("key", key, sizeof(key));)
    DEBUG(dump("iv", iv, sizeof(iv));)
    
    /* Open the output decrypted.zip file. */
    if((out = fopen(argv[3], "wb")) == NULL) {
        perror("failed to open decrypted.zip destination");
        FAIL(-6)
    }
    
    /* Decrypt the zip file. */
    if(!htc_aes_decrypt(in, out, key, iv, chunk_size, progress_update)) {
        fprintf(stderr, "failed to decrypt zip file!\n");
        FAIL(-7) 
    }

    printf("Decrypted RUU (zip) written to: %s\n", argv[3]);

end:
    if(in) fclose(in);
    if(out) fclose(out);
    return rc;
}
