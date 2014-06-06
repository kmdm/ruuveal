#ifndef HTC_AES_H
#define HTC_AES_H
#include <mcrypt.h>
typedef int (*htc_aes_progress_t) (unsigned int, unsigned int, const char *, unsigned int);
typedef int (*htc_aes_crypt_t) (MCRYPT, char *, int, char *, char *);


unsigned int htc_get_num_chunks(unsigned int, unsigned int);
unsigned int htc_get_chunk_size(unsigned char);

int htc_aes_decrypt_chunk(MCRYPT, char *, int, char *, char *);
int htc_aes_encrypt_chunk(MCRYPT, char *, int, char *, char *);

int htc_aes_decrypt(FILE *, unsigned int, FILE *, char *, char *, unsigned char,
                    htc_aes_progress_t);
int htc_aes_encrypt(FILE *, FILE *, char *, char *, unsigned char,
                    htc_aes_progress_t);

#define HTC_AES_KEYSIZE 0x10
#define HTC_AES_READBUF 0x8000
#define HTC_AES_READBUF_ROUNDS 0x20
#define HTC_AES_CHUNK_SIZE 20
#endif

