/* ruuveal - Decrypt HTC encrypted RUUs (rom.zip files).
 *
 * Copyright (C) 2013 Kenny Millington
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
#include <mcrypt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "htcaes.h"

static unsigned int get_num_chunks(unsigned int size, unsigned int chunk_size) 
{
    /* FIXME: This implementation could very well not be complete. */
    unsigned int chunks;
    
    if(chunk_size == 1)
        return size;
    else if(chunk_size - 1 < 1)
        return 0;
    else if(size < chunk_size)
        return 0;
    else if(size == chunk_size)
        return 1;
    
    chunks = size / chunk_size;
    chunks--;
    
    if(size - (chunk_size * chunks) != 0)
        chunks++;

    return chunks;
}

static int decrypt_chunk(MCRYPT td, char *buf, int size, char *key, char *iv)
{
    char new_iv[HTC_AES_KEYSIZE];
    memcpy(new_iv, &buf[size - HTC_AES_KEYSIZE], HTC_AES_KEYSIZE);
    mcrypt_generic_init(td, key, HTC_AES_KEYSIZE, iv);
    mdecrypt_generic(td, buf, size);
    mcrypt_generic_deinit(td);
    memcpy(iv, new_iv, HTC_AES_KEYSIZE);
}

static int encrypt_chunk(MCRYPT td, char *buf, int size, char *key, char *iv)
{
    mcrypt_generic_init(td, key, HTC_AES_KEYSIZE, iv);
    mcrypt_generic(td, buf, size);
    mcrypt_generic_deinit(td);
    memcpy(iv, &buf[size - HTC_AES_KEYSIZE], HTC_AES_KEYSIZE);
}

static int htc_aes_crypt(FILE *in, unsigned int maxlen, 
                         FILE *out, char *key, char *iv, 
                         unsigned char chunks_in, htc_aes_progress_t callback,
                         htc_aes_crypt_t crypt_func)
{
    char buf[HTC_AES_READBUF], orig_iv[HTC_AES_KEYSIZE];
    unsigned int pos, size, chunks, bytes, bytesdone = 0, chunksdone = 0;
    unsigned int count = HTC_AES_READBUF_ROUNDS + 1;
    unsigned int chunk_size = (((int)chunks_in)<<HTC_AES_CHUNK_SIZE); 
    MCRYPT td;

    /* Get size of zip data. */
    pos = ftell(in);
    fseek(in, 0, SEEK_END);
    size = ftell(in) - pos;
    fseek(in, pos, SEEK_SET);
    
    if(maxlen > 0 && maxlen < size) {
        size = maxlen;
    }

    chunks = get_num_chunks(size, chunk_size);
    
    td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, NULL, MCRYPT_CBC, NULL);
    
    if(td == MCRYPT_FAILED) {
        perror("failed to open mcrypt module");
        return 0;
    }

    memcpy(orig_iv, iv, HTC_AES_KEYSIZE);

    while(bytesdone < size && 
          (bytes = fread(buf, sizeof(char), sizeof(buf), in)) > 0) {
        bytesdone += bytes;
        if(bytesdone > size) bytes -= (bytesdone - size);

        if(callback) callback(bytesdone, size);
        if(chunksdone < chunks) {
            if((ftell(in) - bytes - pos) % chunk_size == 0) {
                count = 0;
                memcpy(iv, orig_iv, HTC_AES_KEYSIZE);
            }            
            
            if(count < HTC_AES_READBUF_ROUNDS) {
                crypt_func(td, buf, bytes, key, iv);
                count++;
            } else if(count == HTC_AES_READBUF_ROUNDS) {
                chunksdone++;
                count++;
            }
        }
        fwrite(buf, sizeof(char), bytes, out);
    }

    mcrypt_module_close(td);
    return 1;
}

int htc_aes_decrypt(FILE *in, unsigned int maxlen, FILE *out, char *key, 
                    char *iv, unsigned char chunks, htc_aes_progress_t callback)
{
    return htc_aes_crypt(in,maxlen,out,key,iv,chunks,callback,decrypt_chunk);
}

int htc_aes_encrypt(FILE *in, FILE *out, char *key, char *iv, 
                   unsigned char chunks, htc_aes_progress_t callback)
{
    return htc_aes_crypt(in, -1, out, key, iv, chunks, callback, encrypt_chunk);
}


