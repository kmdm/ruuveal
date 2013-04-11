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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "htczip.h"

static inline unsigned short swap(unsigned short s)
{
    return ((s & 0xff00)>>8) | ((s & 0xff)<<8);
}

static void left_align_mainver_string(char *mainver, int size)
{
    char *p = mainver, *q = p;
    while(*p == '\xff') p++;
    while(*p != '\xff' && p - mainver < size) *(q++) = *(p++);
    *q = 0;
}

static void right_align_mainver_string(char *mainver, int size)
{
    char *p = mainver + size - 1, *q = p;
    while(*p == '\xff' || *p == 0) p--;
    while(*p != '\xff' && p - mainver >= 0) *(q--) = *(p--);
    while(q - mainver >= 0) *(q--) = '\xff';
}

int htc_zip_init_header(htc_zip_header_t *header)
{
    memset(header, 0xff, sizeof(*header));
    memset(header->magic, 0, sizeof(header->magic));
    strcpy(header->magic, HTC_ZIP_HEADER_MAGIC);
    header->keymap_index = HTC_ZIP_HEADER_DEFAULT_KEYMAP;
    header->chunks = HTC_ZIP_HEADER_DEFAULT_CHUNKS;
}

int htc_zip_read_header(FILE *in, htc_zip_header_t *header)
{
    if(fread(header, 1, sizeof(*header), in) != sizeof(*header)) {
        perror("failed to read htc zip header");
        return 0;
    }

    if(strncmp(header->magic, HTC_ZIP_HEADER_MAGIC, 
               strlen(HTC_ZIP_HEADER_MAGIC))) {
        return 0;
    }

    left_align_mainver_string(header->mainver, HTC_ZIP_HEADER_MAINVER_SIZE);

    header->keymap_index = swap(header->keymap_index);
    return 1;
}

int htc_zip_write_header(FILE *out, htc_zip_header_t *header)
{
    int rc = 1;

    header->keymap_index = swap(header->keymap_index);
    right_align_mainver_string(header->mainver, HTC_ZIP_HEADER_MAINVER_SIZE);

    if(fwrite(header, 1, sizeof(*header), out) != sizeof(*header)) {
        perror("failed to write htc zip header");
        rc = 0;
    }

    header->keymap_index = swap(header->keymap_index);
    left_align_mainver_string(header->mainver, HTC_ZIP_HEADER_MAINVER_SIZE);
    return rc;
}
