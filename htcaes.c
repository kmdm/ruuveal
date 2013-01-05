#include <mcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "htcaes.h"

static int get_num_chunks(unsigned int size, unsigned int chunk_size) 
{
    /* TODO: Implement this. */
    return 64;
}

static int decrypt_chunk(MCRYPT td, char *buf, int size, char *key, char *iv)
{
    char new_iv[16];
    memcpy(new_iv, &buf[0x7FF0], 16);
    mcrypt_generic_init(td, key, 16, iv);
    mdecrypt_generic(td, buf, size);
    mcrypt_generic_deinit(td);
    memcpy(iv, new_iv, 16);
}

int htc_aes_decrypt(FILE *in, FILE *out, char *key, char *iv, 
                    unsigned int chunk_size, htc_aes_progress_t callback)
{
    char buf[0x8000], orig_iv[16];
    unsigned int pos, size, chunks, bytes, chunksdone = 0, count = 33;
    
    MCRYPT td;

    /* Get size of zip data. */
    pos = ftell(in);
    fseek(in, 0, SEEK_END);
    size = ftell(in) - pos;
    fseek(in, pos, SEEK_SET);
    
    chunks = get_num_chunks(size, chunk_size);

    td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, NULL, MCRYPT_CBC, NULL);
    
    if(td == MCRYPT_FAILED) {
        perror("failed to open mcrypt module");
        return 0;
    }
    
    memcpy(orig_iv, iv, 16);
    
    while((bytes = fread(buf, sizeof(char), sizeof(buf), in)) > 0) {
        if(callback) callback(ftell(in), size);
        if(chunksdone < chunks) {
            if((ftell(in) - bytes - pos) % chunk_size == 0) {
                count = 0;
                memcpy(iv, orig_iv, 16);
            }            
            
            if(count < 0x20) {
                decrypt_chunk(td, buf, sizeof(buf), key, iv);
                count++;
            } else if(count == 0x20) {
                chunksdone++;
                count++;
            }
        }
        fwrite(buf, sizeof(char), sizeof(buf), out);
    }

    mcrypt_module_close(td);
    return 1;
}
