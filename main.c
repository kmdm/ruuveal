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
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "htcaes.h"
#include "htckey.h"
#include "htczip.h"

#include "htc/devices.h"

#ifdef DEBUG_ENABLED
#define DEBUG(x) x
#else
#define DEBUG(x)
#endif

#define FAIL(x) rc = x; goto end;

static struct {
    char encrypt;
    char info;
    unsigned short keymap_index;
    unsigned int chunks;
    char mainver[HTC_ZIP_HEADER_MAINVER_SIZE];
    char device[32];
    char source[256];
    char dest[256];
    char keydata_file[256];
} opts = {0};

#ifdef DEBUG_ENABLED
static void debug(const char *fmt, ...)
{
    static int prefix = 0;
    va_list args;
    if(prefix == 0) {
        fprintf(stderr, "debug> ");
        prefix = 1;
    }

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    if(strstr(fmt, "\n")) {
        prefix = 0;
    }
}

static void dump(const char *label, const unsigned char *data, int len)
{
    int i;

    debug("%s dump (offset: 0x%08lx, size: %d):-\n",
          label, (unsigned long int)data, len);

    for(i = 0; i < len; i++) {
        debug("%02x ", (unsigned char)data[i]);
        if((i + 1) % 16 == 0)
            debug("\n", i);
    }

    debug("\n");
}
#endif

int usage(char * const *argv)
{
    int i;
    htc_device_t *ptr;

    printf("usage:-\n\n");
    printf("%s [options] --device DEVICE <source.zip> <output.zip>\n\n",
           argv[0]);

    printf("options:-\n\n");
    printf("--info, -I\t\t\tDisplays info about an encrypted zip\n");
    printf("--encrypt, -E\t\t\tSet encryption mode\n");
    printf("--mainver MAINVER, -m\t\tSet the mainver when encrypting\n");
    printf("--key KEYINDEX, -k\t\tSet the encryption key index\n");
    printf("--chunks CHUNKS, -c\t\tSet the number of encryption chunks\n\n");
    printf("--keydata-file, -K\t\tOverride the compiled in keydata\n\n");

    printf("supported devices:-\n\n");
    for(ptr = htc_get_devices(); *ptr->name; ptr++) {
        printf("* %s (%s)\n", ptr->desc, ptr->name);
    }
    printf("\n");

    return -1;
}

void progress_update(unsigned int pos, unsigned int size)
{
    printf("Processing ZIP... %d/%d\r", pos, size);
}

static int parse_opts(int argc, char * const *argv)
{
    int c, index;

    struct option longopts[] = {
        { "encrypt", no_argument, NULL, 'E' },
        { "key", required_argument, NULL, 'k' },
        { "chunks", required_argument, NULL, 'c' },
        { "device", required_argument, NULL, 'd' },
        { "mainver", required_argument, NULL, 'm' },
        { "info", no_argument, NULL, 'I' },
        { "keydata-file", required_argument, NULL, 'K' },
        { 0, 0, 0, 0}
    };

    while(
        (c = getopt_long(argc, argv, "Ek:c:d:m:IK:", longopts, &index)) != -1
    ) switch(c) {
        case 'E':
            opts.encrypt = 1;
        break;
        case 'k':
            opts.keymap_index = (unsigned short)strtoul(optarg, 0, 16);
        break;
        case 'c':
            opts.chunks = (char)strtoul(optarg, 0, 16);
        break;
        case 'd':
            strncpy(opts.device, optarg, sizeof(opts.device));
        break;
        case 'm':
            strncpy(opts.mainver, optarg, sizeof(opts.mainver));
        break;
        case 'I':
            opts.info = 1;
        break;
        case 'K':
            strncpy(opts.keydata_file, optarg, sizeof(opts.keydata_file));
        break;

    }

    if(opts.encrypt && opts.info) {
        return 0;
    } else if(strlen(opts.device) == 0 && strlen(opts.keydata_file) == 0) {
        fprintf(stderr, "error: --device is a required argument.\n\n");
        return 0;
    }

    if(argc - optind < 1) {
        return 0;
    }

    strncpy(opts.source, argv[optind], sizeof(opts.source));

    if(argc - optind >= 2) {
        strncpy(opts.dest, argv[optind+1], sizeof(opts.dest));
    } else if(!opts.info) {
        return 0;
    }

    return 1;
}

int main(int argc, char * const *argv)
{
    char key[HTC_AES_KEYSIZE] = {0};
    char iv[HTC_AES_KEYSIZE] = {0};
    char *keydata = NULL;
    int rc = 0;

    FILE *fh;

    htc_zip_header_t header;

    // FIXME: Better way to set these defaults.
    opts.keymap_index = HTC_ZIP_HEADER_DEFAULT_KEYMAP;
    opts.chunks = HTC_ZIP_HEADER_DEFAULT_CHUNKS;
    strncpy(opts.mainver, HTC_ZIP_HEADER_DEFAULT_MAINVER, sizeof(opts.mainver));

    FILE *in = NULL, *out = NULL;

    printf("ruuveal\n");
    printf("-------\n\n");

    if(!parse_opts(argc, argv)) {
        usage(argv);
        FAIL(-1);
    }

    /* Open the source file. */
    if((in = fopen(opts.source, "rb")) == NULL) {
        perror("failed to open source zip");
        FAIL(-2)
    }

    /* Read the header. */
    if(!opts.encrypt) {
        if(!htc_zip_read_header(in, &header)) {
            fseek(in, 0x100, SEEK_SET);
            if(!htc_zip_read_header(in, &header)) {
                fprintf(stderr, "invalid htc aes encrypted zip file!\n");
                FAIL(-4);
            }
        }

        if(opts.info) {
            printf("encrypted zip info:-\n\n");
            printf("keyindex: 0x%04x\n", header.keymap_index);
            printf("chunks: 0x%02x\n", header.chunks);
            printf("mainver: %.*s\n\n",
                   HTC_ZIP_HEADER_MAINVER_SIZE, header.mainver);
            goto end;
        }

    } else {
        htc_zip_init_header(&header);
        header.keymap_index = opts.keymap_index;
        header.chunks = opts.chunks;
        strncpy(header.mainver, opts.mainver, sizeof(header.mainver));
    }

    if(strlen(opts.keydata_file) > 0) {
        if(!(keydata = malloc(HTC_KEYDATA_LEN))) {
            fprintf(stderr, "failed to allocate memory for keydata!\n");
            FAIL(-8)
        }

        if(!(fh = fopen(opts.keydata_file, "rb"))) {
            fprintf(stderr, "failed to open keydata file: %s\n",
                    opts.keydata_file);
            FAIL(-9)
        }

        if(fread(keydata,sizeof(char),HTC_KEYDATA_LEN,fh) != HTC_KEYDATA_LEN) {
            fprintf(stderr, "failed to read keydata file: %s\n",
                    opts.keydata_file);
            fclose(fh);
            FAIL(-10)
        }

        fclose(fh);
    }

    /* Generate AES/IV for decryption. */
    if(htc_generate_aes_keys(opts.device,
                             header.keymap_index,
                             key, iv, keydata) == 0
    ) {
        fprintf(stderr, "failed to generate htc aes keys\n");
        FAIL(-5)
    }

    DEBUG(dump("key", key, sizeof(key));)
    DEBUG(dump("iv", iv, sizeof(iv));)

    /* Open the output file. */
    if((out = fopen(opts.dest, "wb")) == NULL) {
        perror("failed to open output zip destination");
        FAIL(-6)
    }

    /* Process the zip file. */
    if(opts.encrypt) {
        htc_zip_write_header(out, &header);
        if(!htc_aes_encrypt(in, out, key, iv, header.chunks, progress_update)) {
            fprintf(stderr, "failed to encrypt zip file!\n");
            FAIL(-7)
        }

        printf("Encrypted RUU (zip) written to: %s\n", opts.dest);
    } else {
        if(!htc_aes_decrypt(in, out, key, iv, header.chunks, progress_update)) {
            fprintf(stderr, "failed to decrypt zip file!\n");
            FAIL(-7)
        }

        printf("Decrypted RUU (zip) written to: %s\n", opts.dest);
    }


end:
    if(in) fclose(in);
    if(out) fclose(out);
    return rc;
}
