/* brruuteveal - Brute force decrypt HTC encrypted RUUs (rom.zip files).
 *
 * Copyright (C) 2014 Kenny Millington
 *
 * This file is part of ruuveal.
 *
 * ruuveal is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ruuveal is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ruuveal.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "htcaes.h"
#include "htckey.h"
#include "htclargezip.h"
#include "htczip.h"

#ifdef DEBUG_ENABLED
#define DEBUG(x) x
#else
#define DEBUG(x)
#endif

#define FAIL(x) rc = x; goto end;

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

int usage(char * const *argv)
{
    printf("usage:-\n\n");
    printf("%s [options] <hboot> <source.zip> <output keyfile>\n", argv[0]);
    return -1;
}

static int process_zip(FILE *in, FILE *hb, const char *keyfile)
{
    int i, rc = 0;
    unsigned int chunksize = 0, hbsize = 0;
    char key[HTC_AES_KEYSIZE] = {0};
    char iv[HTC_AES_KEYSIZE] = {0};
    char *chunk = NULL, *spool = NULL, *hboot = NULL;

    FILE *out = NULL;
    htc_zip_header_t header;
    MCRYPT td = NULL;
    
    /* Open encryption module. */
    td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, NULL, MCRYPT_CBC, NULL);
    if(td == MCRYPT_FAILED) {
        perror("failed to open mcrypt module");
        FAIL(-8);
    }
            
    /* Open the output file. */
    if((out = fopen(keyfile, "wb")) == NULL) {
        perror("failed to open output zip destination");
        FAIL(-1)
    }

    /* Read the header. */
    if(!htc_zip_read_header(in, &header)) {
        fseek(in, 0x100, SEEK_CUR);
        if(!htc_zip_read_header(in, &header)) {
            fprintf(stderr, "invalid htc aes encrypted zip file!\n");
            FAIL(-3);
        }
    }

    chunksize = htc_get_chunk_size(header.chunks);
    if(!(chunk = malloc(chunksize))) {
        fprintf(stderr, "failed to generate buffer of chunksize: %u\n", 
                chunksize);
        FAIL(-4);
    }
    
    if(!(spool = malloc(chunksize))) {
        fprintf(stderr, "failed to generate buffer of chunksize: %u\n", 
                chunksize);
        FAIL(-4);
    }

    if(fread(chunk, 1, chunksize, in) != chunksize) {
        fprintf(stderr, "failed to read chunk into buffer!\n");
        FAIL(-5);
    }
    
    /* Determine hboot length. */
    fseek(hb, 0, SEEK_END);
    hbsize = ftell(hb);
    fseek(hb, 0, SEEK_SET);

    if(!(hboot = malloc(hbsize))) {
        fprintf(stderr, "failed to allocate memory for hboot: %u\n", hbsize);
        FAIL(-6)
    }

    if(fread(hboot, sizeof(char), hbsize, hb) != hbsize) {
        fprintf(stderr, "failed to read hboot!\n");
            FAIL(-7)
    }
    
    printf("\n");

    for(i=0x9CE64; i >= 0x9CE64; i--) {
        /* Generate AES/IV for decryption. */
        printf("\rBrute-forcing key: %d/%d...", i, hbsize);
        if(htc_generate_aes_keys(NULL, header.keymap_index, key, iv, 
                                 &hboot[i]) == 0) {
            fprintf(stderr, "failed to generate htc aes keys\n");
            FAIL(-8)
        }
        
        /* Reset the chunk data and decrypt the chunk. */
        memcpy(spool, chunk, chunksize);
        htc_aes_decrypt_chunk(td, spool, chunksize, key, iv);
        

        /* Check for the PK zip header. */
        if(strncmp("PK", spool, 2) == 0) {
            printf("SUCCESS!\n");
            if(fwrite(&hboot[i], 1, HTC_KEYDATA_LEN, out) != HTC_KEYDATA_LEN) {
                fprintf(stderr, "failed to write key data to file!");
                FAIL(-10);
            }
            FAIL(0);
        }
    }

    rc = 1;
end:
    if(chunk) free(chunk);
    if(spool) free(spool);
    if(hboot) free(hboot);
    if(td) mcrypt_module_close(td);
    if(out) fclose(out);
    return rc;
}

int main(int argc, char * const *argv)
{
    int rc = 0;
    char keydata[HTC_KEYDATA_LEN] = {0};
    htc_largezip_header_t hdr;

    FILE *in = NULL, *hb = NULL;
    

    printf("bruuteveal\n");
    printf("-------\n\n");
    
    if(argc < 4) {
        fprintf(stderr, "invalid usage");
        exit(usage(argv));
    }

    /* Open the hboot file. */
    if((hb = fopen(argv[1], "rb")) == NULL) {
        perror("failed to open hboot");
        FAIL(-2)
    }
    
    /* Open the source zip. */
    if((in = fopen(argv[2], "rb")) == NULL) {
        perror("failed to open source zip");
        FAIL(-2)
    }

    /* Check for a "Large Zip" */
    if(htc_largezip_read_header(in, &hdr)) {
        printf("Large zip format detected containing %d zipfile(s)\n",
               hdr.count);

        fseek(in, sizeof(hdr) + hdr.starts[0], SEEK_SET);
        rc = process_zip(in, hb, argv[3]);
    } else {
        rc = process_zip(in, hb, argv[3]);
    }
    
    switch(rc) {
        case 0: 
            printf("Successful bruteveal run, key written to: %s\n", argv[2]);
            break;
        case 1:
            printf("Failed to determine key - Correct HBOOT/RUU pairing?\n");
            break;
        default:
            break;
    }

end:
    if(in) fclose(in);
    if(hb) fclose(hb);
    return rc;
}
