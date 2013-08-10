#ifndef HTCKEY_H
#define HTCKEY_H
#define HTC_KEYDATA_LEN 0x60
int htc_generate_aes_keys(const char *, int, char *, char *, const char *);
#endif
