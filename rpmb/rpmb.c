#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <unistd.h>
#include <scsi/sg.h>

constexpr uint8_t   SECURITY_PROTOCOL_IN  = 0xA2;
constexpr uint8_t   SECURITY_PROTOCOL_OUT = 0xB5;
constexpr uint8_t   UFS_PROTOCOL          = 0xEC;
constexpr uint16_t  RPMB_PROTOCOL         = 0x0001;
constexpr uint16_t  READ_COUNTER          = 0x0002;
constexpr uint16_t  READ_DATA             = 0x0004;
constexpr uint8_t   UNIT_ATTENTION        = 0x06;
constexpr size_t    BLOCK_SIZE            = 256;

static const char  SCSI_GENERIC[] = "/sys/class/scsi_generic";
static const char  RPMB_WLUN[]    = ":49476";

struct rpmb_frame {
  uint8_t  stuff[196];
  uint8_t  mac[32];
  uint8_t  data[BLOCK_SIZE];
  uint8_t  nonce[16];
  uint8_t  write_counter[4];
  uint8_t  address[2];
  uint8_t  block_count[2];
  uint8_t  result[2];
  uint8_t  type[2];
};

static_assert (sizeof (struct rpmb_frame) == 512);

struct rpmb {
  int       fd;
  char      device[PATH_MAX];
  char      sysfs[PATH_MAX];
  uint32_t  blocks;
  uint32_t  per_command;
};

[[noreturn, gnu::format (printf, 1, 2)]] static void
fail (const char *format, ...)
{
  va_list  arguments;

  va_start (arguments, format);
  fputs ("rpmb: ", stderr);
  vfprintf (stderr, format, arguments);
  fputc ('\n', stderr);
  va_end (arguments);
  exit (1);
}

static uint16_t
get_be16 (const uint8_t bytes[static 2])
{
  return (uint16_t)((bytes[0] << 8) | bytes[1]);
}

static uint32_t
get_be32 (const uint8_t bytes[static 4])
{
  return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | bytes[3];
}

static void
put_be16 (uint8_t bytes[static 2], uint16_t value)
{
  bytes[0] = (uint8_t)(value >> 8);
  bytes[1] = (uint8_t)value;
}

static void
put_be32 (uint8_t bytes[static 4], uint32_t value)
{
  put_be16 (bytes, (uint16_t)(value >> 16));
  put_be16 (bytes + 2, (uint16_t)value);
}

static const char *
result_name (uint16_t result)
{
  static const char *const  names[] = {
    "ok", "general failure", "authentication failure", "counter failure", "address failure", "write failure",
    "read failure", "authentication key not programmed",
  };

  return ((result & 0x7F) < sizeof (names) / sizeof (names[0])) ? names[result & 0x7F] : "unknown result";
}

static void
security_protocol (const struct rpmb *rpmb, uint8_t opcode, void *buffer, uint32_t length)
{
  uint8_t  cdb[12] = { opcode, UFS_PROTOCOL };

  put_be16 (cdb + 2, RPMB_PROTOCOL);
  put_be32 (cdb + 6, length);
  for (int attempt = 1;; attempt++) {
    uint8_t      sense[32] = {};
    sg_io_hdr_t  io        = {
      .interface_id    = 'S',
      .dxfer_direction = (opcode == SECURITY_PROTOCOL_OUT) ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV,
      .cmd_len         = sizeof (cdb),
      .mx_sb_len       = sizeof (sense),
      .dxfer_len       = length,
      .dxferp          = buffer,
      .cmdp            = cdb,
      .sbp             = sense,
      .timeout         = 30000,
    };
    bool         descriptor;

    if (ioctl (rpmb->fd, SG_IO, &io) != 0) {
      fail ("SG_IO on %s: %s", rpmb->device, strerror (errno));
    }

    if ((io.info & SG_INFO_OK_MASK) == SG_INFO_OK) {
      return;
    }

    descriptor = (sense[0] & 0x7F) >= 0x72;
    if ((attempt < 3) && (((descriptor ? sense[1] : sense[2]) & 0x0F) == UNIT_ATTENTION)) {
      continue;
    }

    fail ("command 0x%02X on %s: status 0x%02X, host 0x%04X, driver 0x%04X, sense key 0x%X, ASC 0x%02X/0x%02X",
          opcode, rpmb->device, io.status, io.host_status, io.driver_status,
          (descriptor ? sense[1] : sense[2]) & 0x0F, descriptor ? sense[2] : sense[12],
          descriptor ? sense[3] : sense[13]);
  }
}

static void
request (const struct rpmb *rpmb, uint16_t type, uint16_t address, uint16_t count, struct rpmb_frame *responses,
         uint16_t response_count)
{
  struct rpmb_frame         frame = {};
  const struct rpmb_frame  *last  = &responses[response_count - 1];

  if (getrandom (frame.nonce, sizeof (frame.nonce), 0) != sizeof (frame.nonce)) {
    fail ("getrandom: %s", strerror (errno));
  }

  put_be16 (frame.address, address);
  put_be16 (frame.block_count, count);
  put_be16 (frame.type, type);
  security_protocol (rpmb, SECURITY_PROTOCOL_OUT, &frame, sizeof (frame));
  memset (responses, 0, response_count * sizeof (*responses));
  security_protocol (rpmb, SECURITY_PROTOCOL_IN, responses, response_count * (uint32_t)sizeof (*responses));
  if (get_be16 (last->type) != (uint16_t)(type << 8)) {
    fail ("request 0x%04X: response type 0x%04X", type, get_be16 (last->type));
  }

  if ((get_be16 (last->result) & 0x7F) != 0) {
    fail ("request 0x%04X at %u: %s (0x%04X)", type, address, result_name (get_be16 (last->result)),
          get_be16 (last->result));
  }

  if (memcmp (last->nonce, frame.nonce, sizeof (frame.nonce)) != 0) {
    fail ("request 0x%04X at %u: the response carries another nonce", type, address);
  }
}

static uint32_t
sysfs_number (const struct rpmb *rpmb, const char *attribute)
{
  char           path[PATH_MAX * 2];
  char           text[32] = {};
  unsigned long  value;
  char          *end;
  FILE          *file;

  snprintf (path, sizeof (path), "%s/%s", rpmb->sysfs, attribute);
  file = fopen (path, "re");
  if (file == nullptr) {
    return 0;
  }

  if (fgets (text, sizeof (text), file) == nullptr) {
    text[0] = 0;
  }

  fclose (file);
  errno = 0;
  value = strtoul (text, &end, 0);
  return ((errno != 0) || (end == text) || (value > UINT32_MAX)) ? 0 : (uint32_t)value;
}

static void
find_rpmb (struct rpmb *rpmb, const char *device)
{
  char           target[PATH_MAX];
  struct dirent *entry;
  DIR           *directory;
  ssize_t        length;

  if (device != nullptr) {
    const char  *name = strrchr (device, '/');

    snprintf (rpmb->device, sizeof (rpmb->device), "%s", device);
    snprintf (rpmb->sysfs, sizeof (rpmb->sysfs), "%s/%s/device", SCSI_GENERIC, (name != nullptr) ? name + 1 : device);
    return;
  }

  directory = opendir (SCSI_GENERIC);
  if (directory == nullptr) {
    fail ("%s: %s", SCSI_GENERIC, strerror (errno));
  }

  while ((entry = readdir (directory)) != nullptr) {
    if (entry->d_name[0] == '.') {
      continue;
    }

    snprintf (rpmb->sysfs, sizeof (rpmb->sysfs), "%s/%s/device", SCSI_GENERIC, entry->d_name);
    length = readlink (rpmb->sysfs, target, sizeof (target) - 1);
    if ((length > (ssize_t)strlen (RPMB_WLUN)) &&
        (memcmp (target + length - strlen (RPMB_WLUN), RPMB_WLUN, strlen (RPMB_WLUN)) == 0))
    {
      snprintf (rpmb->device, sizeof (rpmb->device), "/dev/%s", entry->d_name);
      closedir (directory);
      return;
    }
  }

  fail ("no SCSI generic device for the RPMB well-known LUN (try -d)");
}

static void
open_rpmb (struct rpmb *rpmb, const char *device)
{
  uint32_t  block_shift;

  find_rpmb (rpmb, device);
  rpmb->fd = open (rpmb->device, O_RDWR | O_CLOEXEC);
  if (rpmb->fd < 0) {
    fail ("%s: %s", rpmb->device, strerror (errno));
  }

  rpmb->blocks      = sysfs_number (rpmb, "unit_descriptor/logical_block_count");
  block_shift       = sysfs_number (rpmb, "unit_descriptor/logical_block_size");
  rpmb->per_command = sysfs_number (rpmb, "../../../geometry_descriptor/rpmb_rw_size");
  if ((rpmb->blocks > 0x10000) || ((rpmb->blocks != 0) && (block_shift != 8))) {
    fail ("%s: unexpected unit descriptor, %u blocks of 2^%u bytes", rpmb->device, rpmb->blocks, block_shift);
  }

  if ((rpmb->per_command == 0) || (rpmb->per_command > 0xFFFF)) {
    rpmb->per_command = 1;
  }
}

static uint32_t
parse_number (const char *text, uint32_t limit)
{
  unsigned long  value;
  char          *end;

  errno = 0;
  value = strtoul (text, &end, 0);
  if ((errno != 0) || (end == text) || (*end != 0) || (value > limit)) {
    fail ("bad number %s", text);
  }

  return (uint32_t)value;
}

static void
read_blocks (const struct rpmb *rpmb, uint32_t address, uint32_t count, FILE *output)
{
  struct rpmb_frame  *frames = calloc (rpmb->per_command, sizeof (*frames));

  if (frames == nullptr) {
    fail ("out of memory");
  }

  for (uint32_t done = 0; done < count;) {
    uint16_t  chunk = (uint16_t)((count - done < rpmb->per_command) ? count - done : rpmb->per_command);

    request (rpmb, READ_DATA, (uint16_t)(address + done), chunk, frames, chunk);
    for (uint16_t index = 0; index < chunk; index++) {
      if (fwrite (frames[index].data, BLOCK_SIZE, 1, output) != 1) {
        fail ("write: %s", strerror (errno));
      }
    }

    done += chunk;
  }

  free (frames);
}

static int
usage (void)
{
  fprintf (stderr, "usage: rpmb [-d DEVICE] counter\n"
                   "       rpmb [-d DEVICE] [-o FILE] read [ADDRESS [COUNT]]\n"
                   "  Reads the UFS RPMB unit: its write counter, or COUNT 256-byte blocks from ADDRESS\n"
                   "  (default: all of it) to FILE or stdout. It only sends read requests.\n"
                   "  DEVICE: the SCSI generic node of the RPMB well-known LUN, found in sysfs by default.\n");
  return 2;
}

int
main (int argc, char **argv)
{
  const char   *device = nullptr;
  const char   *output = nullptr;
  struct rpmb   rpmb   = { .fd = -1 };
  int           option;

  while ((option = getopt (argc, argv, "d:o:h")) != -1) {
    switch (option) {
      case 'd':
        device = optarg;
        break;
      case 'o':
        output = optarg;
        break;
      default:
        return usage ();
    }
  }

  if ((optind < argc) && (strcmp (argv[optind], "counter") == 0) && (optind + 1 == argc) && (output == nullptr)) {
    struct rpmb_frame  frame;

    open_rpmb (&rpmb, device);
    request (&rpmb, READ_COUNTER, 0, 0, &frame, 1);
    printf ("%u\n", get_be32 (frame.write_counter));
    return 0;
  }

  if ((optind < argc) && (strcmp (argv[optind], "read") == 0) && (argc - optind <= 3)) {
    uint32_t  address = 0;
    uint32_t  count;
    FILE     *file = stdout;

    open_rpmb (&rpmb, device);
    if (argc - optind > 1) {
      address = parse_number (argv[optind + 1], 0xFFFF);
    }

    if (argc - optind > 2) {
      count = parse_number (argv[optind + 2], 0x10000);
    } else if (rpmb.blocks != 0) {
      count = (address < rpmb.blocks) ? rpmb.blocks - address : 0;
    } else {
      fail ("%s: unknown size, give COUNT", rpmb.device);
    }

    if ((address + count > 0x10000) || ((rpmb.blocks != 0) && (address + count > rpmb.blocks))) {
      fail ("blocks %u-%u are past the end", address, address + count - 1);
    }

    if (output != nullptr) {
      file = fopen (output, "we");
      if (file == nullptr) {
        fail ("%s: %s", output, strerror (errno));
      }
    } else if (isatty (STDOUT_FILENO)) {
      fail ("stdout is a terminal, give -o FILE");
    }

    read_blocks (&rpmb, address, count, file);
    if (fclose (file) != 0) {
      fail ("%s: %s", (output != nullptr) ? output : "stdout", strerror (errno));
    }

    fprintf (stderr, "rpmb: %u blocks from %u, %u per command, from %s\n", count, address, rpmb.per_command,
             rpmb.device);
    return 0;
  }

  return usage ();
}
