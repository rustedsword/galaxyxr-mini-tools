#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

#include "dm.h"
#include "vold.h"

#define MAPPING         "userdata"
#define METADATA_KEY    "vold/metadata_encryption/key"
#define SYSTEM_KEY      "unencrypted/key"
#define USER_KEYS       "misc/vold/user_keys/de"
#define AVB_SIZE        (64 * 1024)
#define AVB_HEADER      256
#define AVB_PROPERTY    0
#define SYSTEM_VERSION  "com.android.build.system.os_version"
#define SYSTEM_PATCH    "com.android.build.system.security_patch"
#define VENDOR_PATCH    "com.android.build.vendor.security_patch"

static int
find_partition (const char *name, char *device)
{
  char           wanted[128];
  char           path[PATH_MAX];
  char           uevent[1024];
  const char     *line;
  struct dirent  *entry;
  DIR            *block = opendir ("/sys/class/block");
  ssize_t        size;
  int            found = 0;
  int            fd;

  if (block == NULL) {
    return 0;
  }

  snprintf (wanted, sizeof (wanted), "PARTNAME=%s\n", name);
  while ((entry = readdir (block)) != NULL) {
    snprintf (path, sizeof (path), "/sys/class/block/%s/uevent", entry->d_name);
    fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      continue;
    }

    size = read (fd, uevent, sizeof (uevent) - 1);
    close (fd);
    if (size <= 0) {
      continue;
    }

    uevent[size] = '\0';
    line         = strstr (uevent, wanted);
    if ((line != NULL) && ((line == uevent) || (line[-1] == '\n'))) {
      snprintf (device, PATH_MAX, "/dev/%s", entry->d_name);
      found++;
    }
  }

  closedir (block);
  return found;
}

/* Waits: early in the boot the kernel may still be adding the partitions,
 * and it lists one in sysfs before its node opens. */
static int
open_partition (const char *name, char *device)
{
  struct timespec  pause = { 0, 100000000 };
  int              error = ENODEV;
  int              fd = -1;
  int              found;

  for (int tick = 0; tick < 100; tick++) {
    found = find_partition (name, device);
    if (found > 1) {
      fprintf (stderr, "%s: several partitions are named %s\n", program_invocation_short_name, name);
      return -1;
    }

    if (found == 1) {
      fd    = open (device, O_RDONLY | O_CLOEXEC);
      error = errno;
      if ((fd >= 0) || ((error != ENOENT) && (error != ENXIO))) {
        break;
      }
    }

    nanosleep (&pause, NULL);
  }

  if (fd < 0) {
    fprintf (stderr, "%s: partition %s: %s\n", program_invocation_short_name, name, strerror (error));
  }

  return fd;
}

static uint64_t
be64 (const unsigned char *data)
{
  uint64_t  value = 0;

  for (int index = 0; index < 8; index++) {
    value = value << 8 | data[index];
  }

  return value;
}

static void
read_property (struct vold_levels *levels, const char *name, const char *value)
{
  unsigned  parts[3] = { 0 };
  int       used = 0;

  if (strcmp (name, SYSTEM_VERSION) == 0) {
    if ((sscanf (value, "%2u%n.%2u%n.%2u%n", &parts[0], &used, &parts[1], &used, &parts[2], &used) >= 1) &&
        (value[used] == '\0'))
    {
      levels->os_version = (parts[0] * 100 + parts[1]) * 100 + parts[2];
    }
  } else if ((strcmp (name, SYSTEM_PATCH) == 0) || (strcmp (name, VENDOR_PATCH) == 0)) {
    if ((sscanf (value, "%4u-%2u-%2u%n", &parts[0], &parts[1], &parts[2], &used) == 3) && (used == 10) &&
        (value[used] == '\0') && (parts[1] >= 1) && (parts[1] <= 12) && (parts[2] >= 1) && (parts[2] <= 31))
    {
      if (strcmp (name, SYSTEM_PATCH) == 0) {
        levels->os_patch = parts[0] * 100 + parts[1];
      } else {
        levels->vendor_patch = (parts[0] * 100 + parts[1]) * 100 + parts[2];
      }
    }
  }
}

/* KeyMint's OS version and patch levels, which Android takes from the build
 * properties: vbmeta carries the same. */
static int
read_levels (struct vold_levels *levels)
{
  static unsigned char  vbmeta[AVB_SIZE];
  char                  device[PATH_MAX];
  const unsigned char   *descriptor;
  const unsigned char   *body;
  uint64_t              authentication;
  uint64_t              auxiliary;
  uint64_t              offset;
  uint64_t              left = 0;
  uint64_t              length;
  uint64_t              name_size;
  uint64_t              value_size;
  ssize_t               size;
  int                   partition = open_partition ("vbmeta", device);

  if (partition < 0) {
    return -1;
  }

  size = pread (partition, vbmeta, sizeof (vbmeta), 0);
  close (partition);
  memset (levels, 0, sizeof (*levels));
  if ((size >= AVB_HEADER) && (memcmp (vbmeta, "AVB0", 4) == 0)) {
    authentication = be64 (vbmeta + 12);
    auxiliary      = be64 (vbmeta + 20);
    offset         = be64 (vbmeta + 96);
    if ((authentication <= AVB_SIZE) && (auxiliary <= AVB_SIZE) &&
        (AVB_HEADER + authentication + auxiliary <= (uint64_t)size) && (offset <= auxiliary) &&
        (be64 (vbmeta + 104) <= auxiliary - offset))
    {
      descriptor = vbmeta + AVB_HEADER + authentication + offset;
      left       = be64 (vbmeta + 104);
    }
  }

  while (left >= 16) {
    length = be64 (descriptor + 8);
    if (length > left - 16) {
      break;
    }

    body = descriptor + 16;
    if ((be64 (descriptor) == AVB_PROPERTY) && (length >= 18)) {
      name_size  = be64 (body);
      value_size = be64 (body + 8);
      if ((name_size < length) && (value_size < length) && (16 + name_size + 1 + value_size + 1 <= length) &&
          (body[16 + name_size] == '\0') && (body[16 + name_size + 1 + value_size] == '\0'))
      {
        read_property (levels, (const char *)body + 16, (const char *)body + 16 + name_size + 1);
      }
    }

    descriptor += 16 + length;
    left       -= 16 + length;
  }

  if ((levels->os_version == 0) || (levels->os_patch == 0) || (levels->vendor_patch == 0)) {
    fprintf (stderr, "%s: %s has no OS version and patch levels\n", program_invocation_short_name, device);
    return -1;
  }

  return 0;
}

/* A mount without a mount point: it goes away with its descriptor. */
static int
mount_detached (const char *type, const char *source, int read_only, const char *options)
{
  char  buffer[128];
  char  *option;
  char  *value;
  int   mount = -1;
  int   fs = fsopen (type, FSOPEN_CLOEXEC);
  int   ok = (fs >= 0) && (fsconfig (fs, FSCONFIG_SET_STRING, "source", source, 0) == 0);

  if (ok && read_only) {
    ok = fsconfig (fs, FSCONFIG_SET_FLAG, "ro", NULL, 0) == 0;
  }

  snprintf (buffer, sizeof (buffer), "%s", options);
  for (option = strtok (buffer, ","); ok && (option != NULL); option = strtok (NULL, ",")) {
    value = strchr (option, '=');
    if (value == NULL) {
      ok = fsconfig (fs, FSCONFIG_SET_FLAG, option, NULL, 0) == 0;
    } else {
      *value++ = '\0';
      ok       = fsconfig (fs, FSCONFIG_SET_STRING, option, value, 0) == 0;
    }
  }

  if (ok && (fsconfig (fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0) == 0)) {
    mount = fsmount (fs, FSMOUNT_CLOEXEC,
                     MOUNT_ATTR_NOATIME | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | (read_only ? MOUNT_ATTR_RDONLY : 0));
  }

  if (mount < 0) {
    fprintf (stderr, "%s: mount %s (%s): %s\n", program_invocation_short_name, source, type, strerror (errno));
  }

  if (fs >= 0) {
    close (fs);
  }

  return mount;
}

static int
read_metadata_key (unsigned char *key)
{
  char  device[PATH_MAX];
  int   read_only = 1;
  int   was_read_only = 0;
  int   result = -1;
  int   partition = open_partition ("metadata", device);
  int   metadata;

  if (partition < 0) {
    return -1;
  }

  /* Even a read-only ext4 mount writes its errors into a writable partition. */
  if ((ioctl (partition, BLKROGET, &was_read_only) != 0) || (ioctl (partition, BLKROSET, &read_only) != 0)) {
    fprintf (stderr, "%s: BLKROSET %s: %s\n", program_invocation_short_name, device, strerror (errno));
  } else {
    metadata = mount_detached ("ext4", device, 1, "noload,errors=remount-ro");
    if (metadata >= 0) {
      result = vold_decrypt_key (metadata, METADATA_KEY, key);
      close (metadata);
    }

    ioctl (partition, BLKROSET, &was_read_only);
  }

  close (partition);
  return result;
}

static int
map_userdata (int read_only)
{
  unsigned char  key[VOLD_KEY_SIZE];
  char           device[PATH_MAX];
  char           slave[PATH_MAX + 64];
  uint64_t       sectors;
  dev_t          mapping;
  int            mapped_read_only;
  int            partition = open_partition ("userdata", device);
  int            result;

  if (partition < 0) {
    return -1;
  }

  close (partition);
  result = dm_find (MAPPING, &mapping, &mapped_read_only);
  if (result < 0) {
    return -1;
  }

  if (result > 0) {
    snprintf (slave, sizeof (slave), "/sys/dev/block/%u:%u/slaves/%s", major (mapping), minor (mapping),
              strrchr (device, '/') + 1);
    if (access (slave, F_OK) != 0) {
      fprintf (stderr, "%s: /dev/mapper/" MAPPING " is not a mapping of %s\n", program_invocation_short_name, device);
      return -1;
    }

    /* A read-only f2fs mount still writes its recovery into a writable device. */
    if (mapped_read_only != read_only) {
      fprintf (stderr, "%s: /dev/mapper/" MAPPING " is %s: %s -r, or remove the mapping\n",
               program_invocation_short_name, mapped_read_only ? "read-only" : "writable",
               mapped_read_only ? "use" : "omit");
      return -1;
    }

    return 0;
  }

  if (read_metadata_key (key) != 0) {
    return -1;
  }

  result = vold_map_default_key (device, MAPPING, key, read_only, &mapping, &sectors);
  explicit_bzero (key, sizeof (key));
  return result;
}

static int
add_fbe_keys (int data)
{
  unsigned char  key[VOLD_KEY_SIZE];
  char           path[PATH_MAX];
  struct dirent  *user;
  DIR            *users;
  int            root = openat (data, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  int            result = -1;

  if (root < 0) {
    fprintf (stderr, "%s: open " MAPPING ": %s\n", program_invocation_short_name, strerror (errno));
    return -1;
  }

  if ((vold_decrypt_key (data, SYSTEM_KEY, key) == 0) && (vold_add_fscrypt_key (root, key, NULL) == 0)) {
    result = 0;
    users  = fdopendir (openat (data, USER_KEYS, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    while ((users != NULL) && ((user = readdir (users)) != NULL)) {
      if (user->d_name[0] == '.') {
        continue;
      }

      snprintf (path, sizeof (path), USER_KEYS "/%s", user->d_name);
      if ((vold_decrypt_key (data, path, key) != 0) || (vold_add_fscrypt_key (root, key, NULL) != 0)) {
        fprintf (stderr, "%s: user %s DE key not added\n", program_invocation_short_name, user->d_name);
      }
    }

    if (users != NULL) {
      closedir (users);
    }
  }

  explicit_bzero (key, sizeof (key));
  close (root);
  return result;
}

int
main (int argc, char **argv)
{
  struct vold_levels  levels;
  const char          *mountpoint = NULL;
  int                 read_only = 0;
  int                 option;
  int                 target;
  int                 data;

  while ((option = getopt (argc, argv, "r")) != -1) {
    if (option != 'r') {
      optind = argc;
      break;
    }

    read_only = 1;
  }

  if (argc - optind == 1) {
    mountpoint = argv[optind];
  }

  if (mountpoint == NULL) {
    fprintf (stderr, "usage: mount_android_userdata [-r] MOUNTPOINT\n"
                     "  mounts Android's encrypted userdata partition on MOUNTPOINT (-r: read-only) and adds\n"
                     "  its file-based encryption keys, decrypted with Samsung's KeyMint TA through /dev/qsee\n");
    return 2;
  }

  target = open (mountpoint, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (target < 0) {
    fprintf (stderr, "%s: %s: %s\n", program_invocation_short_name, mountpoint, strerror (errno));
    return 1;
  }

  atexit (vold_keymint_stop);
  if ((read_levels (&levels) != 0) || (vold_keymint_start (&levels) != 0) || (map_userdata (read_only) != 0)) {
    return 1;
  }

  data = mount_detached ("f2fs", "/dev/mapper/" MAPPING, read_only,
                         read_only ? "inlinecrypt,norecovery" : "inlinecrypt");
  if ((data < 0) || (add_fbe_keys (data) != 0)) {
    return 1;
  }

  vold_keymint_stop ();
  if (move_mount (data, "", target, "", MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH) != 0) {
    fprintf (stderr, "%s: %s: %s\n", program_invocation_short_name, mountpoint, strerror (errno));
    return 1;
  }

  return 0;
}
