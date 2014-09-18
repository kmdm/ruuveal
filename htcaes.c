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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include "htcaes.h"

unsigned int htc_get_num_chunks(unsigned int size, unsigned int chunk_size)
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

unsigned int htc_get_chunk_size(unsigned char chunks)
{
    return ((int)chunks)<<HTC_AES_CHUNK_SIZE;
}

int htc_aes_decrypt_chunk(char *buf, int size, char *key, char *iv)
{
    AES_KEY dec_key;

    AES_set_decrypt_key(key, 8*HTC_AES_KEYSIZE, &dec_key);
    AES_cbc_encrypt(buf, buf, size, &dec_key, iv, AES_DECRYPT);
}

int htc_aes_encrypt_chunk(char *buf, int size, char *key, char *iv)
{
    AES_KEY enc_key;

    AES_set_encrypt_key(key, 8*HTC_AES_KEYSIZE, &enc_key);
    AES_cbc_encrypt(buf, buf, size, &enc_key, iv, AES_ENCRYPT);
}

static int htc_aes_crypt(FILE *in, unsigned int maxlen,
                         FILE *out, char *key, char *iv,
                         unsigned char chunks_in, htc_aes_progress_t callback,
                         htc_aes_crypt_t crypt_func)
{
    char buf[HTC_AES_READBUF], orig_iv[HTC_AES_KEYSIZE];
    unsigned int pos, size, chunks, bytes, bytesdone = 0, chunksdone = 0;
    unsigned int count = HTC_AES_READBUF_ROUNDS + 1;
    unsigned int chunk_size = htc_get_chunk_size(chunks_in);

    /* Get size of zip data. */
    pos = ftell(in);
    fseek(in, 0, SEEK_END);
    size = ftell(in) - pos;
    fseek(in, pos, SEEK_SET);

    if(maxlen > 0 && maxlen < size) {
        size = maxlen;
    }

    chunks = htc_get_num_chunks(size, chunk_size);

    memcpy(orig_iv, iv, HTC_AES_KEYSIZE);

    while(bytesdone < size &&
          (bytes = fread(buf, sizeof(char), sizeof(buf), in)) > 0) {
        bytesdone += bytes;
        if(bytesdone > size) bytes -= (bytesdone - size);

        if(chunksdone < chunks) {
            if((ftell(in) - bytes - pos) % chunk_size == 0) {
                count = 0;
                memcpy(iv, orig_iv, HTC_AES_KEYSIZE);
            }

            if(count < HTC_AES_READBUF_ROUNDS) {
                crypt_func(buf, bytes, key, iv);
                count++;
            } else if(count == HTC_AES_READBUF_ROUNDS) {
                chunksdone++;
                count++;
            }
        }
        fwrite(buf, sizeof(char), bytes, out);

        if(callback) {
            if(!callback(bytesdone, size, buf, bytes)) {
                return 0;
            }
        }
    }

    return 1;
}

int htc_aes_decrypt(FILE *in, unsigned int maxlen, FILE *out, char *key,
                    char *iv, unsigned char chunks, htc_aes_progress_t callback)
{
    return htc_aes_crypt(in,maxlen,out,key,iv,chunks,callback,htc_aes_decrypt_chunk);
}

int htc_aes_encrypt(FILE *in, FILE *out, char *key, char *iv,
                   unsigned char chunks, htc_aes_progress_t callback)
{
    return htc_aes_crypt(in, -1, out, key, iv, chunks, callback, htc_aes_encrypt_chunk);
}


