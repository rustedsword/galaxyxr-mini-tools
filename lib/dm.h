#ifndef DM_H_
#define DM_H_

#include <stdint.h>
#include <sys/types.h>

struct dm_target {
  uint64_t      start;
  uint64_t      sectors;
  const char    *type;
  const char    *params;
};

/* 1 when the mapping NAME exists, 0 when it doesn't */
int
dm_find (const char *name, dev_t *device, int *read_only);

int
dm_create (const char *name, const struct dm_target *targets, int count, int read_only, dev_t *device);

#endif
