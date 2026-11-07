#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <linux/dm-ioctl.h>

#include "dm.h"

#define DM_CONTROL  "/dev/mapper/control"
#define TABLE_SIZE  4096

/* libdevmapper's udev cookie ABI: flags in the high half, cookie base in the
 * low half. A zero base sends flags without waiting for udev, which may not be up. */
#define DM_UDEV_FLAGS_SHIFT           16
#define DM_UDEV_PRIMARY_SOURCE_FLAG   0x0040U

static int
dm_ioctl (int control, unsigned long request, const char *name, struct dm_ioctl *io)
{
  io->version[0] = DM_VERSION_MAJOR;
  io->version[1] = 0;
  io->version[2] = 0;
  snprintf (io->name, sizeof (io->name), "%s", name);
  return ioctl (control, request, io);
}

static int
replace_link (const char *path, const char *target)
{
  char  directory[] = "/dev/mapper/.dm-link-XXXXXX";
  char  temporary[sizeof (directory) + 5];
  int   error = 0;

  if (mkdtemp (directory) == NULL) {
    return -1;
  }

  snprintf (temporary, sizeof (temporary), "%s/link", directory);
  if (symlink (target, temporary) != 0 || rename (temporary, path) != 0) {
    error = errno;
    unlink (temporary);
  }
  rmdir (directory);
  if (error != 0) {
    errno = error;
    return -1;
  }

  return 0;
}

static int
link_device (const char *name, dev_t device)
{
  char         path[DM_NAME_LEN + 16];
  char         target[32];
  struct stat  st;

  /* devtmpfs makes /dev/dm-N when the mapping is created. Leave /dev/mapper
   * as symlinks, which udev can take over when it starts. */
  snprintf (path, sizeof (path), "/dev/mapper/%s", name);
  snprintf (target, sizeof (target), "../dm-%u", minor (device));
  if (symlink (target, path) == 0) {
    return 0;
  }

  if (errno != EEXIST || lstat (path, &st) != 0) {
    return -1;
  }

  if (S_ISLNK (st.st_mode)) {
    if (stat (path, &st) == 0) {
      /* udev may have made the link already. */
      if (S_ISBLK (st.st_mode) && st.st_rdev == device) {
        return 0;
      }
      errno = EEXIST;
      return -1;
    }
    if (errno != ENOENT) {
      return -1;
    }
  } else if (!S_ISBLK (st.st_mode) || st.st_rdev != device) {
    errno = EEXIST;
    return -1;
  }

  /* Replace a dangling link or a matching legacy block node without leaving
   * a gap in the mapper path. An unrelated file or live device stays intact. */
  return replace_link (path, target);
}

static int
load_table (int control, const char *name, const struct dm_target *targets, int count, int read_only)
{
  union {
    struct dm_ioctl  io;
    unsigned char    raw[sizeof (struct dm_ioctl) + TABLE_SIZE];
  }                      request;
  struct dm_target_spec  *spec;
  size_t                 used = sizeof (struct dm_ioctl);
  int                    result;

  memset (&request, 0, sizeof (request));
  for (int index = 0; index < count; index++) {
    size_t  params = strlen (targets[index].params) + 1;
    size_t  size   = sizeof (struct dm_target_spec) + ((params + 7) & ~(size_t)7);

    if (used + size > sizeof (request)) {
      errno = E2BIG;
      return -1;
    }

    spec               = (struct dm_target_spec *)(request.raw + used);
    spec->sector_start = targets[index].start;
    spec->length       = targets[index].sectors;
    spec->next         = size;
    snprintf (spec->target_type, sizeof (spec->target_type), "%s", targets[index].type);
    memcpy (spec + 1, targets[index].params, params);
    used += size;
  }

  request.io.data_size    = used;
  request.io.data_start   = sizeof (struct dm_ioctl);
  request.io.target_count = count;
  request.io.flags        = read_only ? DM_READONLY_FLAG : 0;
  result                  = dm_ioctl (control, DM_TABLE_LOAD, name, &request.io);
  explicit_bzero (&request, sizeof (request));
  return result;
}

int
dm_create (const char *name, const struct dm_target *targets, int count, int read_only, dev_t *device)
{
  struct dm_ioctl  io;
  const char       *step;
  int              control;
  int              error;

  mkdir ("/dev/mapper", 0755);
  control = open (DM_CONTROL, O_RDWR | O_CLOEXEC);
  if (control < 0) {
    fprintf (stderr, "%s: open " DM_CONTROL ": %s\n", program_invocation_short_name, strerror (errno));
    return -1;
  }

  memset (&io, 0, sizeof (io));
  io.data_size = sizeof (io);
  if (dm_ioctl (control, DM_DEV_CREATE, name, &io) != 0) {
    fprintf (stderr, "%s: DM_DEV_CREATE %s: %s\n", program_invocation_short_name, name, strerror (errno));
    close (control);
    return -1;
  }

  step = "DM_TABLE_LOAD";
  if (load_table (control, name, targets, count, read_only) == 0) {
    step = "resume";
    memset (&io, 0, sizeof (io));
    io.data_size = sizeof (io);
    io.event_nr  = DM_UDEV_PRIMARY_SOURCE_FLAG << DM_UDEV_FLAGS_SHIFT;
    if (dm_ioctl (control, DM_DEV_SUSPEND, name, &io) == 0) {
      step = "symlink";
      if (link_device (name, io.dev) == 0) {
        *device = io.dev;
        close (control);
        return 0;
      }
    }
  }

  error = errno;
  memset (&io, 0, sizeof (io));
  io.data_size = sizeof (io);
  dm_ioctl (control, DM_DEV_REMOVE, name, &io);
  close (control);
  fprintf (stderr, "%s: %s %s: %s\n", program_invocation_short_name, step, name, strerror (error));
  return -1;
}
