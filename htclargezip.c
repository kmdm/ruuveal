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

#include "htclargezip.h"

int htc_largezip_read_header(FILE *in, htc_largezip_header_t *header)
{
    int pos = ftell(in);

    if(fread(header, 1, sizeof(*header), in) != sizeof(*header)) {
        printf("%d\n", sizeof(*header));
        perror("failed to read htc largezip header");
        fseek(in, pos, SEEK_SET);
        return 0;
    }

    if(strncmp(header->magic, HTC_LARGEZIP_HEADER_MAGIC,
               strlen(HTC_LARGEZIP_HEADER_MAGIC))) {
        fseek(in, pos, SEEK_SET);
        return 0;
    }

    return 1;
}
