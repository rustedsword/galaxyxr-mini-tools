#ifndef VOLD_H_
#define VOLD_H_

#include <stdint.h>
#include <sys/types.h>

#define VOLD_KEY_SIZE  64

struct vold_levels {
  uint32_t    os_version;
  uint32_t    os_patch;
  uint32_t    vendor_patch;
};

int
vold_keymint_start (const struct vold_levels *levels);

void
vold_keymint_stop (void);

int
vold_decrypt_key (int at, const char *dir, unsigned char *key);

int
vold_map_default_key (const char *device, const char *name, const unsigned char *key, int read_only, dev_t *mapping,
                      uint64_t *sectors);

int
vold_add_fscrypt_key (int fd, const unsigned char *key, unsigned char *identifier);

#endif
