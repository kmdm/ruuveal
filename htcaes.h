#ifndef HTC_AES_H
#define HTC_AES_H
typedef void (*htc_aes_progress_t) (unsigned int, unsigned int);
int htc_aes_decrypt(FILE *, FILE *, char *, char *, unsigned int, 
                    htc_aes_progress_t);

#define HTC_AES_KEYSIZE 0x10
#define HTC_AES_READBUF 0x8000
#define HTC_AES_READBUF_ROUNDS 0x20

#endif

