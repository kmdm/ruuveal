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
#include <string.h>

#include "htc/devices.h"
#include "htc/keydata.h"
#include "htc/keymap.h"

static int get_keydata_offset(const char *device)
{
    int i;
    htc_device_t *ptr;

    for(ptr = htc_get_devices(); *ptr->name; ptr++) {
        if(!strcmp(ptr->name, device)) {
            return ptr->keydata_offset;
        }
    }

    return -1;    
}

int htc_generate_aes_keys(const char *device, int keymap_offset, char *aeskey, 
                          char *aesiv)
{
    char *keymap, *keydata;
    int i, offset;

    if((offset = get_keydata_offset(device)) == -1) {
        return 0;
    }
    
    if((keymap_offset - 1)<<5 >= sizeof(htc_keymap)) {
        return 0;
    }

    keymap = &htc_keymap[(keymap_offset-1)<<5];
    keydata = &htc_keydata[offset * 96];
    
    for(i=0; i < 0x10; i++) {
        aeskey[i] = keydata[keymap[i]];
        aesiv[i]  = keydata[keymap[i + 0x10]];
    }

    return 1;
}
