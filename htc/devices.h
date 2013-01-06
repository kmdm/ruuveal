#ifndef HTC_DEVICES_H
#define HTC_DEVICES_H
typedef struct {
    char name[32];
    char desc[128];
    int keydata_offset;
} htc_device_t;

htc_device_t *htc_get_devices();
#endif

