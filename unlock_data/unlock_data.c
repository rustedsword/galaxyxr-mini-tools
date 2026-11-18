#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <linux/fscrypt.h>

#include "vold.h"

static int
create_mapping (const char *device, const char *name, const unsigned char *key, int read_only)
{
  uint64_t  sectors;
  dev_t     mapping;

  if (vold_map_default_key (device, name, key, read_only, &mapping, &sectors) != 0) {
    return 1;
  }

  printf ("/dev/mapper/%s %u:%u, %llu sectors\n", name, major (mapping), minor (mapping), (unsigned long long)sectors);
  return 0;
}

static int
add_fbe_key (const char *mountpoint, const unsigned char *key)
{
  unsigned char  identifier[FSCRYPT_KEY_IDENTIFIER_SIZE];
  int            fd = open (mountpoint, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  int            index;
  int            result;

  if (fd < 0) {
    fprintf (stderr, "unlock_data: open the mount point\n");
    return 1;
  }

  result = vold_add_fscrypt_key (fd, key, identifier);
  close (fd);
  if (result != 0) {
    return 1;
  }

  printf ("key identifier ");
  for (index = 0; index < FSCRYPT_KEY_IDENTIFIER_SIZE; index++) {
    printf ("%02x", identifier[index]);
  }

  printf ("\n");
  return 0;
}

int
main (int argc, char **argv)
{
  struct vold_levels  levels = { 0 };
  unsigned char       key[VOLD_KEY_SIZE];
  int                 read_only = 0;
  int                 option;
  int                 status;

  while ((option = getopt (argc, argv, "rv:p:V:")) != -1) {
    if (option == 'r') {
      read_only = 1;
    } else if (option == 'v') {
      levels.os_version = strtoul (optarg, NULL, 10);
    } else if (option == 'p') {
      levels.os_patch = strtoul (optarg, NULL, 10);
    } else if (option == 'V') {
      levels.vendor_patch = strtoul (optarg, NULL, 10);
    } else {
      return 2;
    }
  }

  if ((levels.os_version == 0) || (levels.os_patch == 0) || (levels.vendor_patch == 0) ||
      (((argc - optind != 4) || (strcmp (argv[optind], "metadata") != 0)) &&
       ((argc - optind != 3) || (strcmp (argv[optind], "fbe") != 0))))
  {
    fprintf (stderr, "usage: unlock_data [-r] -v OS_VERSION -p OS_PATCH -V VENDOR_PATCH metadata KEYDIR DEVICE NAME\n"
                     "       unlock_data [...] fbe KEYDIR MOUNTPOINT\n"
                     "  decrypts a vold key with Samsung's KeyMint TA through /dev/qsee, then creates the\n"
                     "  dm-default-key mapping /dev/mapper/NAME (-r: read-only) or adds the key to MOUNTPOINT's filesystem\n");
    return 2;
  }

  if (vold_keymint_start (&levels) != 0) {
    return 1;
  }

  status = vold_decrypt_key (AT_FDCWD, argv[optind + 1], key);
  vold_keymint_stop ();
  if (status != 0) {
    return 1;
  }

  if (strcmp (argv[optind], "metadata") == 0) {
    status = create_mapping (argv[optind + 2], argv[optind + 3], key, read_only);
  } else {
    status = add_fbe_key (argv[optind + 2], key);
  }

  explicit_bzero (key, sizeof (key));
  return status;
}
