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

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include "htcaes.h"
#include "htckey.h"
#include "htclargezip.h"
#include "htczip.h"

typedef struct {
    int current;
    unsigned int size;
    unsigned int step;
    int mode;
    int result;
    char *hboot;
    char chunk[HTC_AES_KEYSIZE];
    int keymap_index;
    #ifdef HAVE_PTHREAD_H
    pthread_mutex_t *mutex;
    #endif
} work_t;

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
    printf("%s <hboot> <source.zip> <output keyfile>\n", argv[0]);
    return -1;
}

static int prepare_buffers(FILE *in, FILE *hb, char *chunk, 
                           char **hboot, unsigned int *hbsize, 
                           htc_zip_header_t *header)
{
    int rc = 0;

    /* Read the header. */
    if(!htc_zip_read_header(in, header)) {
        fseek(in, 0x100, SEEK_CUR);
        if(!htc_zip_read_header(in, header)) {
            fprintf(stderr, "invalid htc aes encrypted zip file!\n");
            FAIL(-3);
        }
    }

    if(fread(chunk, 1, HTC_AES_KEYSIZE, in) != HTC_AES_KEYSIZE) {
        fprintf(stderr, "failed to read chunk into buffer!\n");
        FAIL(-5);
    }
    
    /* Determine hboot length. */
    fseek(hb, 0, SEEK_END);
    *hbsize = ftell(hb);
    fseek(hb, 0, SEEK_SET);

    if(!(*hboot = malloc(*hbsize))) {
        fprintf(stderr, "failed to allocate memory for hboot: %u\n", *hbsize);
        FAIL(-6)
    }

    if(fread(*hboot, sizeof(char), *hbsize, hb) != *hbsize) {
        fprintf(stderr, "failed to read hboot!\n");
            FAIL(-7)
    }
    
end:
    return rc;
}

static int try_aes_keydata(char *keydata, int keymap_index, char *chunk)
{
    char spool[HTC_AES_KEYSIZE], key[HTC_AES_KEYSIZE], iv[HTC_AES_KEYSIZE];

    if(htc_generate_aes_keys(NULL, keymap_index, key, iv, 
                             keydata) == 0) {
        fprintf(stderr, "failed to generate htc aes keys\n");
        return -1;
    }

    /* Reset the chunk data and decrypt the chunk. */
    memcpy(spool, chunk, sizeof(spool));
    htc_aes_decrypt_chunk(spool, sizeof(spool), key, iv);

    /* Check for the PK zip header. */
    if(strncmp("PK\003\004", spool, 4) == 0) {
        return 1;
    }

    return 0;

}

static int get_next_position(work_t *work)
{
    int pos = 0;

    #ifdef HAVE_PTHREAD_H
    pthread_mutex_lock(work->mutex);
    #endif
    
    if(work->result == -1) {
        work->current -= work->step;
        DEBUG(debug("WC becomes: %d, WC size: %d\n", work->current, work->size));
        if(work->current < 0) {
            work->current = work->size;
            DEBUG(debug("WC reset: %d\n", work->current));

            switch(++work->mode) {
                case 1: // 2-byte aligned
                    work->current += 2;
                case 0: // 4-byte aligned
                    work->current -= (work->size % 4);
                    work->step = 4;
                    break;
                case 2: // no alignment
                    work->current -= (work->size % 2);
                    work->current++;
                    work->step = 2;
                    break;
                default: // we're done
                    work->result = -2;
                    pos = -1;
            }

            DEBUG(debug("pos: %d, wc: %d, m: %d, s: %d, sz: %d\n\n", 
                  pos, work->current, work->mode, work->step, work->size));

        }

        if(pos != -1) {
            pos = work->current;
        }
    } else {
        // abort if result found
        pos = -1;
    }


    #ifdef HAVE_PTHREAD_H
    pthread_mutex_unlock(work->mutex);
    #endif

    return pos;
}

static void do_work(void *ptr)
{
    int i = 0;
    work_t *work = (work_t *)ptr;
     
    while((i = get_next_position(work)) != -1) {
        printf("\rBrute-forcing key[loop %d]: %d/%d...\r",
               work->mode + 1, i, work->size);

        /* Generate AES/IV for decryption. */
        if(try_aes_keydata(&work->hboot[i],
                           work->keymap_index, work->chunk) == 1) {
            // FIXME: No mutex lock
            work->result = i;
            printf("SUCCESS!\n");
            break;
        }
    }
}

static int process_zip(FILE *in, FILE *hb, const char *keyfile, int threads)
{
    int t, rc = 0;
    

    FILE *out = NULL;
    htc_zip_header_t header;
    work_t work;
    
    #ifdef HAVE_PTHREAD_H
    pthread_t pthreads[threads];
    #endif

    /* Open the output file. */
    if((out = fopen(keyfile, "wb")) == NULL) {
        perror("failed to open output zip destination");
        FAIL(-1)
    }
    
    if(prepare_buffers(in, hb, work.chunk, &work.hboot, &work.size, &header) != 0) {
        FAIL(-2)
    }
    
    DEBUG(debug("Size: %d\n", work.size));

    /* poor man's initialization (read "lazy"). */
    work.current = 0;
    work.mode = -1;
    work.step = 1;
    work.result = -1;
    work.keymap_index = header.keymap_index;
    
    #ifdef HAVE_PTHREAD_H
    work.mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(work.mutex, NULL);
    for(t=0; t < threads; t++) {
        pthread_create(&pthreads[t], NULL, &do_work, (void *)&work);
    }
    for(t=0; t < threads; t++) {
        pthread_join(pthreads[t], NULL);
    }
    pthread_mutex_destroy(work.mutex);
    #else
    do_work(&work);
    #endif

    if(work.result > -1) {
        if(fwrite(&work.hboot[work.result], 1, HTC_KEYDATA_LEN, out) != 
                  HTC_KEYDATA_LEN) {
            perror("failed to write key data to file");
            FAIL(-3);
        }
    } else {
        rc = 1;
        printf("NOT FOUND!\n");
    }

end:
    if(work.hboot) free(work.hboot);
    if(out) fclose(out);
    return rc;
}

int main(int argc, char * const *argv)
{
    int rc = 0;
    char keydata[HTC_KEYDATA_LEN] = {0};
    htc_largezip_header_t hdr;

    FILE *in = NULL, *hb = NULL;
    

    printf("bruutveal\n");
    printf("---------\n\n");
    
    if(argc < 4) {
        exit(usage(argv));
    }

    /* Open the hboot file. */
    if((hb = fopen(argv[1], "rb")) == NULL) {
        perror("failed to open hboot");
        FAIL(-1)
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
    }
        
    rc = process_zip(in, hb, argv[3], 1);
    
    switch(rc) {
        case 0: 
            printf("Successful bruutveal run, key written to: %s\n", argv[3]);
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
