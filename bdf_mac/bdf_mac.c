#include <ctype.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BOARD_NAME             "bus=pci,vendor=17cb,device=1107,subsystem-vendor=17cb,subsystem-device=1107," \
                               "qmi-chip-id=2,qmi-board-id=255"
/* qcom,calibration-variant of the wifi@0 node */
#define BOARD_VARIANT          "Samsung_Galaxy_XR"
#define REGDB_NAME             "bus=pci"
#define BOARD_MAGIC            "QCA-ATH12K-BOARD"
#define IE_BOARD               0
#define IE_REGDB               1
#define IE_NAME                0
#define IE_DATA                1
#define SEGMENT_SIZE           0x15400
#define SEGMENT_CHECKSUM       0x0a
#define SEGMENT_MAC            0x0e
#define SEGMENT_USE_BOARD_MAC  0x1e
#define SEAL_SIZE              32

struct buffer {
  uint8_t  *data;
  size_t   size;
};

struct sha256 {
  uint32_t  state[8];
  uint8_t   block[64];
  uint64_t  size;
};

static const uint32_t sha256_k[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const uint8_t seal_salt[8] = { 0x62, 0x4d, 0x6d, 0x3c, 0x5a, 0x4a, 0x24, 0x28 };

__attribute__ ((noreturn)) static void
fail (const char *what)
{
  fprintf (stderr, "bdf_mac: %s\n", what);
  exit (1);
}

static uint32_t
le32 (const uint8_t *bytes)
{
  return bytes[0] | bytes[1] << 8 | bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static uint32_t
ror (uint32_t value, int bits)
{
  return (value >> bits) | (value << (32 - bits));
}

static void
sha256_block (struct sha256 *ctx)
{
  uint32_t  w[64];
  uint32_t  s[8];

  for (int i = 0; i < 16; i++) {
    w[i] = (uint32_t)ctx->block[4 * i] << 24 | ctx->block[4 * i + 1] << 16 | ctx->block[4 * i + 2] << 8 |
           ctx->block[4 * i + 3];
  }

  for (int i = 16; i < 64; i++) {
    w[i] = w[i - 16] + (ror (w[i - 15], 7) ^ ror (w[i - 15], 18) ^ (w[i - 15] >> 3)) + w[i - 7] +
           (ror (w[i - 2], 17) ^ ror (w[i - 2], 19) ^ (w[i - 2] >> 10));
  }

  memcpy (s, ctx->state, sizeof (s));
  for (int i = 0; i < 64; i++) {
    uint32_t  t1 = s[7] + (ror (s[4], 6) ^ ror (s[4], 11) ^ ror (s[4], 25)) + ((s[4] & s[5]) ^ (~s[4] & s[6])) +
                   sha256_k[i] + w[i];
    uint32_t  t2 = (ror (s[0], 2) ^ ror (s[0], 13) ^ ror (s[0], 22)) + ((s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]));

    memmove (s + 1, s, 7 * sizeof (*s));
    s[4] += t1;
    s[0]  = t1 + t2;
  }

  for (int i = 0; i < 8; i++) {
    ctx->state[i] += s[i];
  }
}

static void
sha256_init (struct sha256 *ctx)
{
  static const uint32_t  initial[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

  memcpy (ctx->state, initial, sizeof (initial));
  ctx->size = 0;
}

static void
sha256_update (struct sha256 *ctx, const uint8_t *data, size_t size)
{
  while (size > 0) {
    size_t  used  = ctx->size % 64;
    size_t  chunk = (size < 64 - used) ? size : 64 - used;

    memcpy (ctx->block + used, data, chunk);
    ctx->size += chunk;
    data      += chunk;
    size      -= chunk;
    if (ctx->size % 64 == 0) {
      sha256_block (ctx);
    }
  }
}

static void
sha256_final (struct sha256 *ctx, uint8_t digest[32])
{
  uint8_t   tail[64 + 8] = { 0x80 };
  uint64_t  bits         = ctx->size * 8;
  size_t    padding      = 64 - (ctx->size + 8) % 64;

  for (int i = 0; i < 8; i++) {
    tail[padding + i] = bits >> (56 - 8 * i);
  }

  sha256_update (ctx, tail, padding + 8);
  for (int i = 0; i < 32; i++) {
    digest[i] = ctx->state[i / 4] >> (24 - 8 * (i % 4));
  }
}

/* The upstream firmware checks this trailer on board data and regdb */
static void
seal (const uint8_t *body, size_t size, uint8_t mac[SEAL_SIZE])
{
  uint8_t        key[64] = { 0 };
  uint8_t        inner[32];
  struct sha256  ctx;

  sha256_init (&ctx);
  sha256_update (&ctx, body, size);
  sha256_final (&ctx, key);
  memcpy (key + 32, seal_salt, sizeof (seal_salt));

  for (int i = 0; i < 64; i++) {
    key[i] ^= 0x36;
  }

  sha256_init (&ctx);
  sha256_update (&ctx, key, sizeof (key));
  sha256_update (&ctx, body, size);
  sha256_final (&ctx, inner);

  for (int i = 0; i < 64; i++) {
    key[i] ^= 0x36 ^ 0x5c;
  }

  sha256_init (&ctx);
  sha256_update (&ctx, key, sizeof (key));
  sha256_update (&ctx, inner, sizeof (inner));
  sha256_final (&ctx, mac);
}

static void
parse_mac (const char *text, uint8_t mac[6])
{
  uint8_t  bits = 0;

  if (strlen (text) != 17) {
    fail ("invalid MAC");
  }

  for (int i = 0; i < 6; i++) {
    char  hex[3] = { text[3 * i], text[3 * i + 1], 0 };

    if (!isxdigit ((unsigned char)hex[0]) || !isxdigit ((unsigned char)hex[1]) || ((i < 5) && (text[3 * i + 2] != ':'))) {
      fail ("invalid MAC");
    }

    mac[i] = strtoul (hex, NULL, 16);
    bits  |= mac[i];
  }

  if ((bits == 0) || (mac[0] & 1)) {
    fail ("MAC is not a unicast address");
  }
}

static struct buffer
read_file (const char *path)
{
  struct buffer  file = { 0 };
  struct stat    info;
  int            fd;

  fd = open (path, O_RDONLY | O_CLOEXEC);
  if ((fd < 0) || (fstat (fd, &info) != 0) || ((file.data = malloc (info.st_size + SEAL_SIZE)) == NULL) ||
      (read (fd, file.data, info.st_size) != info.st_size))
  {
    fprintf (stderr, "bdf_mac: cannot read %s\n", path);
    exit (1);
  }

  close (fd);
  file.size = info.st_size;
  return file;
}

static void
strip_seal (struct buffer *file)
{
  uint8_t  expected[SEAL_SIZE];

  if (file->size > SEAL_SIZE) {
    seal (file->data, file->size - SEAL_SIZE, expected);
    if (memcmp (expected, file->data + file->size - SEAL_SIZE, SEAL_SIZE) == 0) {
      file->size -= SEAL_SIZE;
    }
  }
}

static void
add_seal (struct buffer *file)
{
  seal (file->data, file->size, file->data + file->size);
  file->size += SEAL_SIZE;
}

static void
patch_board (struct buffer *elf, const uint8_t mac[6])
{
  uint8_t   *segment;
  uint32_t  phdr;
  uint16_t  checksum = 0;

  if ((elf->size < SEGMENT_SIZE) || (memcmp (elf->data, "\177ELF\1\1", 6) != 0)) {
    fail ("BDWLAN is not a 32-bit little-endian ELF file");
  }

  phdr = le32 (elf->data + 0x1c);
  if ((phdr > elf->size - 0x20) || (le32 (elf->data + phdr + 16) != SEGMENT_SIZE) ||
      (le32 (elf->data + phdr + 4) > elf->size - SEGMENT_SIZE))
  {
    fail ("BDWLAN has no WCN7850 board data segment");
  }

  segment = elf->data + le32 (elf->data + phdr + 4);
  for (size_t i = 0; i < SEGMENT_SIZE; i += 2) {
    checksum ^= segment[i] | segment[i + 1] << 8;
  }

  if (checksum != 0xffff) {
    fail ("BDWLAN board data has a bad checksum");
  }

  memcpy (segment + SEGMENT_MAC, mac, 6);
  segment[SEGMENT_USE_BOARD_MAC] = 1;
  segment[SEGMENT_CHECKSUM]      = 0;
  segment[SEGMENT_CHECKSUM + 1]  = 0;
  checksum                       = 0;
  for (size_t i = 0; i < SEGMENT_SIZE; i += 2) {
    checksum ^= segment[i] | segment[i + 1] << 8;
  }

  checksum                      ^= 0xffff;
  segment[SEGMENT_CHECKSUM]      = checksum;
  segment[SEGMENT_CHECKSUM + 1]  = checksum >> 8;
}

static void
put (struct buffer *out, const void *data, size_t size)
{
  out->data = realloc (out->data, out->size + size + 3);
  if (out->data == NULL) {
    fail ("out of memory");
  }

  memcpy (out->data + out->size, data, size);
  out->size += size;
  while (out->size % 4 != 0) {
    out->data[out->size++] = 0;
  }
}

static void
put_ie (struct buffer *out, uint32_t id, const void *data, size_t size)
{
  uint8_t  header[8];

  for (int i = 0; i < 4; i++) {
    header[i]     = id >> (8 * i);
    header[4 + i] = size >> (8 * i);
  }

  put (out, header, sizeof (header));
  put (out, data, size);
}

static void
write_file (const char *path, const struct buffer *out)
{
  int  fd = open (path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);

  if ((fd < 0) || (write (fd, out->data, out->size) != (ssize_t)out->size) || (close (fd) != 0)) {
    unlink (path);
    fail ("write OUT");
  }
}

int
main (int argc, char **argv)
{
  struct buffer  board, regdb, mac_file;
  struct buffer  board_ie = { 0 }, regdb_ie = { 0 }, out = { 0 };
  uint8_t        mac[6];

  if (argc != 5) {
    fprintf (stderr, "usage: bdf_mac BDWLAN REGDB MAC_FILE OUT\n"
                     "  writes an ath12k board-2.bin for the Galaxy XR's WCN7850: Samsung's board data\n"
                     "  (/vendor/firmware/kiwi/bdwlan.elf) with the factory MAC (/mnt/vendor/efs/wifi/.mac.info)\n"
                     "  and Samsung's regdb (/vendor/firmware/kiwi/regdb.bin), both sealed\n");
    return 2;
  }

  mac_file = read_file (argv[3]);
  while ((mac_file.size > 0) && (mac_file.data[mac_file.size - 1] == '\n')) {
    mac_file.size--;
  }

  mac_file.data[mac_file.size] = 0;
  parse_mac ((const char *)mac_file.data, mac);

  board = read_file (argv[1]);
  strip_seal (&board);
  patch_board (&board, mac);
  add_seal (&board);

  regdb = read_file (argv[2]);
  strip_seal (&regdb);
  add_seal (&regdb);

  put_ie (&board_ie, IE_NAME, BOARD_NAME ",variant=" BOARD_VARIANT, strlen (BOARD_NAME ",variant=" BOARD_VARIANT));
  put_ie (&board_ie, IE_NAME, BOARD_NAME, strlen (BOARD_NAME));
  put_ie (&board_ie, IE_DATA, board.data, board.size);
  put_ie (&regdb_ie, IE_NAME, REGDB_NAME, strlen (REGDB_NAME));
  put_ie (&regdb_ie, IE_DATA, regdb.data, regdb.size);
  put (&out, BOARD_MAGIC, sizeof (BOARD_MAGIC));
  put_ie (&out, IE_BOARD, board_ie.data, board_ie.size);
  put_ie (&out, IE_REGDB, regdb_ie.data, regdb_ie.size);

  write_file (argv[4], &out);
  return 0;
}
