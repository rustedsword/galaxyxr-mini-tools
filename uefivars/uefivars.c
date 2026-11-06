#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

constexpr uint32_t  PTBL_MAGIC    = 0x4C425450;
constexpr uint32_t  STORE_MAGIC   = 0x72745344;
constexpr uint32_t  TABLE_MAGIC   = 0x32524156;
constexpr size_t    PTBL_HEADER   = 16;
constexpr size_t    PTBL_ENTRY    = 16;
constexpr size_t    STORE_HEADER  = 48;
constexpr size_t    TABLE_HEADER  = 20;
constexpr size_t    GROUP_HEADER  = 20;
constexpr size_t    RECORD_HEADER = 18;
constexpr size_t    RECORD_FIXED  = 20;
constexpr size_t    PREVIEW       = 16;

struct image {
  const char  *path;
  uint8_t     *bytes;
  size_t       size;
};

struct store {
  const uint8_t  *header;
  const uint8_t  *data;
  size_t          data_size;
  char            copy;
};

[[noreturn, gnu::format (printf, 1, 2)]] static void
fail (const char *format, ...)
{
  va_list  arguments;

  va_start (arguments, format);
  fputs ("uefivars: ", stderr);
  vfprintf (stderr, format, arguments);
  fputc ('\n', stderr);
  va_end (arguments);
  exit (1);
}

static uint16_t
get_le16 (const uint8_t bytes[static 2])
{
  return (uint16_t)(bytes[0] | (bytes[1] << 8));
}

static uint32_t
get_le32 (const uint8_t bytes[static 4])
{
  return bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static size_t
align4 (size_t value)
{
  return (value + 3) & ~(size_t)3;
}

static uint32_t
crc32 (const uint8_t *bytes, size_t size)
{
  uint32_t  crc = 0xFFFFFFFF;

  for (size_t index = 0; index < size; index++) {
    crc ^= bytes[index];
    for (int bit = 0; bit < 8; bit++) {
      crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
  }

  return ~crc;
}

static void
read_image (struct image *image)
{
  FILE    *file     = (strcmp (image->path, "-") == 0) ? stdin : fopen (image->path, "rbe");
  size_t   capacity = 0;
  size_t   got;

  if (file == nullptr) {
    fail ("%s: %s", image->path, strerror (errno));
  }

  do {
    if (image->size == capacity) {
      capacity     = (capacity == 0) ? (1 << 20) : capacity * 2;
      image->bytes = realloc (image->bytes, capacity);
      if (image->bytes == nullptr) {
        fail ("out of memory");
      }
    }

    got          = fread (image->bytes + image->size, 1, capacity - image->size, file);
    image->size += got;
  } while (got != 0);

  if (ferror (file)) {
    fail ("%s: read error", image->path);
  }

  if (file != stdin) {
    fclose (file);
  }
}

static const uint8_t *
store_header (const struct image *image, size_t offset, size_t sector)
{
  const uint8_t  *header;
  uint16_t        version;
  size_t          covered;

  if ((offset > image->size) || (image->size - offset < sector)) {
    return nullptr;
  }

  header  = image->bytes + offset;
  version = get_le16 (header + 4);
  covered = ((version >= 0x100) && (version <= 0x102)) ? 508 : 40;
  if ((get_le32 (header) != STORE_MAGIC) || (version > 0x104) || (get_le16 (header + 8) != 1) ||
      (crc32 (header, covered) != get_le32 (header + covered)))
  {
    return nullptr;
  }

  return header;
}

static bool
find_store (const struct image *image, const uint8_t *entry, size_t sector, struct store *store)
{
  size_t          base   = get_le16 (entry + 4) * sector;
  size_t          half   = (get_le16 (entry + 6) & ~1u) / 2;
  const uint8_t  *copies[2];
  int             active;
  size_t          sectors;

  if (half < 3) {
    return false;
  }

  for (int copy = 0; copy < 2; copy++) {
    const uint8_t  *header  = store_header (image, base + copy * half * sector, sector);
    size_t          trailer = base + (copy * half + half - 1) * sector;

    copies[copy] = ((header != nullptr) && (trailer + STORE_HEADER <= image->size) &&
                    (memcmp (header, image->bytes + trailer, STORE_HEADER) == 0)) ? header : nullptr;
  }

  if ((copies[0] != nullptr) && (copies[1] != nullptr)) {
    unsigned  generation_a = get_le16 (copies[0] + 6) & 3;
    unsigned  generation_b = get_le16 (copies[1] + 6) & 3;

    if (generation_a == ((generation_b + 1) & 3)) {
      active = 0;
    } else if (generation_b == ((generation_a + 1) & 3)) {
      active = 1;
    } else {
      fprintf (stderr, "uefivars: partition 0x%x: copies at generations %u and %u, skipped\n", get_le32 (entry),
               generation_a, generation_b);
      return false;
    }
  } else if ((copies[0] != nullptr) || (copies[1] != nullptr)) {
    active = (copies[0] != nullptr) ? 0 : 1;
  } else {
    return false;
  }

  sectors = get_le16 (copies[active] + 12);
  if ((sectors > half - 2) || (base + (active * half + 1 + sectors) * sector > image->size)) {
    return false;
  }

  store->header    = copies[active];
  store->data      = image->bytes + base + (active * half + 1) * sector;
  store->data_size = sectors * sector;
  store->copy      = (char)('A' + active);
  return true;
}

static size_t
find_sector_size (const struct image *image, uint32_t partitions)
{
  static const size_t  sizes[] = { 512, 4096 };
  unsigned             best_hits = 0;
  size_t               best      = 0;

  for (size_t index = 0; index < sizeof (sizes) / sizeof (sizes[0]); index++) {
    unsigned  hits = 0;

    for (uint32_t partition = 0; partition < partitions; partition++) {
      struct store  store;

      hits += find_store (image, image->bytes + PTBL_HEADER + partition * PTBL_ENTRY, sizes[index], &store);
    }

    if (hits > best_hits) {
      best_hits = hits;
      best      = sizes[index];
    }
  }

  if (best == 0) {
    fail ("%s: no partition holds a data store", image->path);
  }

  return best;
}

static void
print_attributes (uint32_t attributes)
{
  static const char *const  names[] = { "NV", "BS", "RT", "HR", "AW", "AT", "AP", "EA" };

  for (size_t bit = 0; bit < sizeof (names) / sizeof (names[0]); bit++) {
    if ((attributes & (1u << bit)) != 0) {
      printf (" %s", names[bit]);
    }
  }

  if ((attributes >> 8) != 0) {
    printf (" 0x%x", attributes & ~0xFFu);
  }
}

static void
print_name (const uint8_t *name, size_t size)
{
  for (size_t index = 0; index + 1 < size; index += 2) {
    uint16_t  unit = get_le16 (name + index);

    if (unit == 0) {
      break;
    }

    if ((unit < 0x20) || ((unit >= 0xD800) && (unit < 0xE000))) {
      putchar ('?');
    } else if (unit < 0x80) {
      putchar (unit);
    } else if (unit < 0x800) {
      putchar (0xC0 | (unit >> 6));
      putchar (0x80 | (unit & 0x3F));
    } else {
      putchar (0xE0 | (unit >> 12));
      putchar (0x80 | ((unit >> 6) & 0x3F));
      putchar (0x80 | (unit & 0x3F));
    }
  }
}

static void
print_bytes (const uint8_t *bytes, size_t size, bool full)
{
  if (!full) {
    for (size_t index = 0; (index < size) && (index < PREVIEW); index++) {
      printf (" %02x", bytes[index]);
    }

    puts ((size > PREVIEW) ? " ..." : "");
    return;
  }

  putchar ('\n');
  for (size_t line = 0; line < size; line += 16) {
    printf ("    %04zx ", line);
    for (size_t index = line; index < line + 16; index++) {
      if (index < size) {
        printf (" %02x", bytes[index]);
      } else {
        printf ("   ");
      }
    }

    printf ("  ");
    for (size_t index = line; (index < line + 16) && (index < size); index++) {
      putchar (isprint (bytes[index]) ? bytes[index] : '.');
    }

    putchar ('\n');
  }
}

static void
print_table (const struct store *store, bool full)
{
  const uint8_t  *table = store->data;
  size_t          used  = get_le32 (table + 8);

  if ((used < TABLE_HEADER) || (used > store->data_size)) {
    puts ("  bad table size");
    return;
  }

  if (crc32 (table, used) != get_le32 (store->header + 20)) {
    puts ("  table CRC mismatch, listing anyway");
  }

  for (size_t group = TABLE_HEADER; used - group >= GROUP_HEADER;) {
    size_t          group_end = group + get_le32 (table + group);
    const uint8_t  *guid      = table + group + 4;

    if ((group_end < group + GROUP_HEADER) || (group_end > used)) {
      printf ("  bad group at 0x%zx\n", group);
      return;
    }

    for (size_t record = group + GROUP_HEADER; group_end - record >= RECORD_HEADER;) {
      size_t  record_size = get_le32 (table + record);
      size_t  data_size   = get_le32 (table + record + 12);
      size_t  name_size   = get_le16 (table + record + 16);
      size_t  data_offset = align4 (RECORD_HEADER + name_size);
      size_t  fixed       = RECORD_FIXED + align4 (name_size) + align4 (data_size);

      if ((record_size < RECORD_HEADER) || (record_size > group_end - record) || (data_offset > record_size) ||
          (data_size > record_size - data_offset))
      {
        printf ("  bad record at 0x%zx\n", record);
        return;
      }

      printf ("  ");
      print_name (table + record + RECORD_HEADER, name_size);
      printf ("-%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x %zu", get_le32 (guid), get_le16 (guid + 4),
              get_le16 (guid + 6), guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15],
              data_size);
      if (record_size > fixed) {
        printf ("+%zu", record_size - fixed);
      }

      putchar (':');
      print_bytes (table + record + data_offset, data_size, full);
      record += record_size;
    }

    group = group_end;
  }
}

static int
usage (void)
{
  fprintf (stderr, "usage: uefivars [-x] IMAGE\n"
                   "  Lists the UEFI variables that uefisecapp keeps in IMAGE: a dump of the RPMB\n"
                   "  (rpmb read) or of a uefivarstore partition, - for stdin. -x prints all data.\n");
  return 2;
}

int
main (int argc, char **argv)
{
  struct image  image = {};
  bool          full  = false;
  uint32_t      partitions;
  size_t        sector;
  int           option;

  while ((option = getopt (argc, argv, "xh")) != -1) {
    if (option != 'x') {
      return usage ();
    }

    full = true;
  }

  if (optind + 1 != argc) {
    return usage ();
  }

  image.path = argv[optind];
  read_image (&image);
  if ((image.size < PTBL_HEADER) || (get_le32 (image.bytes) != PTBL_MAGIC)) {
    fail ("%s: no PTBL partition table at the start", image.path);
  }

  partitions = get_le32 (image.bytes + 12);
  if (partitions > (image.size - PTBL_HEADER) / PTBL_ENTRY) {
    fail ("%s: %u partitions don't fit", image.path, partitions);
  }

  sector = find_sector_size (&image, partitions);
  printf ("%s: %u partitions, %zu-byte sectors\n", image.path, partitions, sector);
  for (uint32_t partition = 0; partition < partitions; partition++) {
    const uint8_t  *entry = image.bytes + PTBL_HEADER + partition * PTBL_ENTRY;
    struct store    store;

    if (!find_store (&image, entry, sector, &store) || (store.data_size < TABLE_HEADER) ||
        (get_le32 (store.data) != TABLE_MAGIC))
    {
      continue;
    }

    printf ("partition %u, owner ", get_le32 (entry));
    for (size_t index = 8; index < PTBL_ENTRY; index++) {
      printf ("%02x", entry[index]);
    }

    putchar (':');
    print_attributes (get_le32 (store.data + 16));
    printf (", copy %c, write %u, %u of %zu bytes\n", store.copy, get_le32 (store.header + 16),
            get_le32 (store.data + 8), store.data_size);
    print_table (&store, full);
  }

  return 0;
}
