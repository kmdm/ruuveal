#ifndef HTC_LARGEZIP_H
#define HTC_LARGEZIP_HEADER_MAGIC "LaR@eZip"
typedef struct {
    char magic[8];
    unsigned int starts[8];
    unsigned int lengths[8];
    unsigned int count;
    unsigned int unknown;
    char padding[0x100 - (8 + ((8 + 8 + 1 + 1)*4))];
} htc_largezip_header_t;

int htc_largezip_read_header(FILE *, htc_largezip_header_t *);
#endif
