#ifndef HTC_ZIP_H
#define HTC_ZIP_HEADER_MAGIC "Htc@egi$"
#define HTC_ZIP_HEADER_DEFAULT_CHUNKS 0x0A
#define HTC_ZIP_HEADER_DEFAULT_KEYMAP 0xA4
#define HTC_ZIP_HEADER_DEFAULT_MAINVER "0.00.0000.0"
#define HTC_ZIP_HEADER_MAINVER_SIZE 11
typedef struct {
    char magic[8];
    unsigned short keymap_index;
    unsigned char chunks;
    char padding1[9];
    char mainver[HTC_ZIP_HEADER_MAINVER_SIZE];
    char padding2[1];
    unsigned int unknown;
    char padding3[92];
} htc_zip_header_t;

int htc_zip_init_header(htc_zip_header_t *);
int htc_zip_read_header(FILE *, htc_zip_header_t *);
int htc_zip_write_header(FILE *, htc_zip_header_t *);
#endif
