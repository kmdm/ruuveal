#ifndef HTC_DEVICES_H
#define HTC_DEVICES_H
typedef struct {
    char name[32];
    int keydata_offset;
} htc_device_t;

htc_device_t htc_devices[] = {
    { "evita"      , 0 },
    { "ville"      , 1 },
    { "jewel"      , 2 },
    { "jel_dd"     , 3 },
    { "fireball"   , 4 },
    { "endeavor_u" , 6 }
};

unsigned int htc_devices_len = 6;
#endif
