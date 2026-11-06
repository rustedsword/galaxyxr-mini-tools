#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <linux/fs.h>

#include "dm.h"

#define GEOMETRY_OFFSET  4096
#define GEOMETRY_MAGIC   0x616C4467
#define METADATA_OFFSET  (GEOMETRY_OFFSET + 2 * 4096)
#define HEADER_MAGIC     0x414C5030
#define HEADER_MAJOR     10
#define TARGET_LINEAR    0
#define TARGET_ZERO      1
#define MAX_EXTENTS      32

struct lp_geometry {
  uint32_t  magic;
  uint32_t  struct_size;
  uint8_t   checksum[32];
  uint32_t  metadata_max_size;
  uint32_t  metadata_slot_count;
  uint32_t  logical_block_size;
} __attribute__ ((packed));

struct lp_table {
  uint32_t  offset;
  uint32_t  num_entries;
  uint32_t  entry_size;
} __attribute__ ((packed));

struct lp_header {
  uint32_t         magic;
  uint16_t         major_version;
  uint16_t         minor_version;
  uint32_t         header_size;
  uint8_t          header_checksum[32];
  uint32_t         tables_size;
  uint8_t          tables_checksum[32];
  struct lp_table  partitions;
  struct lp_table  extents;
  struct lp_table  groups;
  struct lp_table  block_devices;
} __attribute__ ((packed));

struct lp_partition {
  char      name[36];
  uint32_t  attributes;
  uint32_t  first_extent_index;
  uint32_t  num_extents;
  uint32_t  group_index;
} __attribute__ ((packed));

struct lp_extent {
  uint64_t  num_sectors;
  uint32_t  target_type;
  uint64_t  target_data;
  uint32_t  target_source;
} __attribute__ ((packed));

struct metadata {
  struct lp_header  header;
  unsigned char     *tables;
  dev_t             super;
  uint64_t          super_sectors;
};

__attribute__ ((noreturn)) static void
fail (const char *what)
{
  fprintf (stderr, "map_super: %s\n", what);
  exit (1);
}

static const void *
entry (const struct metadata *metadata, const struct lp_table *table, uint32_t index, size_t size)
{
  if ((table->entry_size < size) || (index >= table->num_entries) ||
      ((uint64_t)table->offset + (uint64_t)table->num_entries * table->entry_size > metadata->header.tables_size))
  {
    fail ("metadata table out of bounds");
  }

  return metadata->tables + table->offset + (size_t)index * table->entry_size;
}

static void
read_metadata (const char *device, struct metadata *metadata)
{
  struct lp_geometry  geometry;
  struct stat         info;
  uint64_t            bytes;
  int                 fd;

  fd = open (device, O_RDONLY | O_CLOEXEC);
  if ((fd < 0) || (fstat (fd, &info) != 0) || !S_ISBLK (info.st_mode) || (ioctl (fd, BLKGETSIZE64, &bytes) != 0)) {
    fail ("open the super block device");
  }

  if ((pread (fd, &geometry, sizeof (geometry), GEOMETRY_OFFSET) != sizeof (geometry)) ||
      (geometry.magic != GEOMETRY_MAGIC) || (geometry.struct_size != sizeof (geometry)))
  {
    fail ("no LP geometry");
  }

  if ((pread (fd, &metadata->header, sizeof (metadata->header), METADATA_OFFSET) != sizeof (metadata->header)) ||
      (metadata->header.magic != HEADER_MAGIC) || (metadata->header.major_version != HEADER_MAJOR) ||
      (metadata->header.header_size < sizeof (metadata->header)) ||
      ((uint64_t)metadata->header.header_size + metadata->header.tables_size > geometry.metadata_max_size))
  {
    fail ("no LP metadata in slot 0");
  }

  metadata->tables = malloc (metadata->header.tables_size);
  if ((metadata->tables == NULL) ||
      (pread (fd, metadata->tables, metadata->header.tables_size, METADATA_OFFSET + metadata->header.header_size) !=
       (ssize_t)metadata->header.tables_size))
  {
    fail ("read the LP tables");
  }

  close (fd);
  metadata->super         = info.st_rdev;
  metadata->super_sectors = bytes / 512;
}

static void
map_partition (const struct metadata *metadata, const char *name)
{
  const struct lp_partition  *partition = NULL;
  struct dm_target           targets[MAX_EXTENTS];
  char                       params[MAX_EXTENTS][48];
  uint64_t                   sectors = 0;
  dev_t                      device;

  for (uint32_t index = 0; index < metadata->header.partitions.num_entries; index++) {
    const struct lp_partition  *candidate = entry (metadata, &metadata->header.partitions, index, sizeof (*candidate));

    if (strncmp (candidate->name, name, sizeof (candidate->name)) == 0) {
      partition = candidate;
      break;
    }
  }

  if ((partition == NULL) || (strlen (name) >= sizeof (partition->name))) {
    fprintf (stderr, "map_super: no partition %s\n", name);
    exit (1);
  }

  if ((partition->num_extents == 0) || (partition->num_extents > MAX_EXTENTS)) {
    fail ("unsupported extent count");
  }

  for (uint32_t index = 0; index < partition->num_extents; index++) {
    const struct lp_extent  *extent = entry (metadata, &metadata->header.extents, partition->first_extent_index + index,
                                             sizeof (*extent));

    params[index][0]       = 0;
    targets[index].start   = sectors;
    targets[index].sectors = extent->num_sectors;
    targets[index].params  = params[index];
    if (extent->target_type == TARGET_ZERO) {
      targets[index].type = "zero";
    } else if ((extent->target_type == TARGET_LINEAR) && (extent->target_source == 0) &&
               (extent->target_data <= metadata->super_sectors) &&
               (extent->num_sectors <= metadata->super_sectors - extent->target_data))
    {
      targets[index].type = "linear";
      snprintf (params[index], sizeof (params[index]), "%u:%u %llu", major (metadata->super), minor (metadata->super),
                (unsigned long long)extent->target_data);
    } else {
      fail ("unsupported extent");
    }

    sectors += extent->num_sectors;
  }

  if (dm_create (name, targets, partition->num_extents, 1, &device) != 0) {
    exit (1);
  }

  printf ("/dev/mapper/%s %u:%u, %llu sectors\n", name, major (device), minor (device), (unsigned long long)sectors);
}

int
main (int argc, char **argv)
{
  struct metadata  metadata;

  if (argc < 3) {
    fprintf (stderr, "usage: map_super SUPER NAME...\n"
                     "  maps logical partitions of a non-A/B super partition read-only as /dev/mapper/NAME\n");
    return 2;
  }

  read_metadata (argv[1], &metadata);
  for (int index = 2; index < argc; index++) {
    map_partition (&metadata, argv[index]);
  }

  return 0;
}
