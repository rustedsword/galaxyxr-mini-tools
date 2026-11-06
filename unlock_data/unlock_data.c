#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
#include <linux/fs.h>
#include <linux/fscrypt.h>

#include "dm.h"

#define QSEE_DEVICE        "/dev/qsee"
#define TA_NAME            "skeymast"
#define FRAME              102528
#define KEY_SIZE           64
#define GCM_NONCE          12
#define GCM_TAG            16
#define SECDISCARDABLE     "Android secdiscardable SHA512"
#define DM_OPTIONS         "3 allow_discards sector_size:4096 iv_large_sectors"
#define MAX_FILE           (64 * 1024)
#define NUMBER(tag, value)       { (tag), (value), NULL, 0 }
#define BYTES(tag, data, size)   { (tag), 0, (data), (size) }

enum {
  KM_CONFIGURE  = 15,
  KM_BEGIN      = 8,
  KM_UPDATE     = 9,
  KM_FINISH     = 10,
  KM_ABORT      = 11
};

enum {
  TAG_BLOCK_MODE     = 0x20000004,
  TAG_PADDING        = 0x20000006,
  TAG_OS_VERSION     = 0x300002C1,
  TAG_OS_PATCH       = 0x300002C2,
  TAG_VENDOR_PATCH   = 0x300002CE,
  TAG_SEC_OS_VERSION = 0x30000325,
  TAG_SEC_OS_PATCH   = 0x30000326,
  TAG_SEC_VENDOR     = 0x30000332,
  TAG_MAC_LENGTH     = 0x300003EB,
  TAG_NOW            = 0x60000320,
  TAG_APPLICATION_ID = 0x90000259,
  TAG_NONCE          = 0x900003E9
};

struct buffer {
  unsigned char    *data;
  size_t           size;
  size_t           capacity;
};

struct param {
  uint32_t             tag;
  uint64_t             number;
  const unsigned char  *bytes;
  size_t               size;
};

struct reply {
  long                 err;
  uint64_t             long0;
  int                  has_long0;
  const unsigned char  *bin0;
  size_t               bin0_size;
};

static unsigned char  frame[FRAME + 5];
static unsigned char  answer[FRAME + 4];
static int            qsee = -1;
static int            read_only;
static uint32_t       os_version;
static uint32_t       os_patch;
static uint32_t       vendor_patch;

static void
fail (const char *what)
{
  fprintf (stderr, "unlock_data: %s\n", what);
  exit (1);
}

static void
put (struct buffer *out, const void *data, size_t size)
{
  if (out->size + size > out->capacity) {
    out->capacity = (out->size + size) * 2 + 256;
    out->data     = realloc (out->data, out->capacity);
    if (out->data == NULL) {
      fail ("out of memory");
    }
  }

  memcpy (out->data + out->size, data, size);
  out->size += size;
}

static void
put_tlv (struct buffer *out, unsigned char tag, const void *content, size_t size)
{
  unsigned char  header[6] = { tag };
  size_t         used = 2;

  if (size < 0x80) {
    header[1] = (unsigned char)size;
  } else if (size < 0x100) {
    header[1] = 0x81;
    header[2] = (unsigned char)size;
    used      = 3;
  } else if (size < 0x10000) {
    header[1] = 0x82;
    header[2] = (unsigned char)(size >> 8);
    header[3] = (unsigned char)size;
    used      = 4;
  } else {
    header[1] = 0x83;
    header[2] = (unsigned char)(size >> 16);
    header[3] = (unsigned char)(size >> 8);
    header[4] = (unsigned char)size;
    used      = 5;
  }

  put (out, header, used);
  put (out, content, size);
}

static void
put_integer (struct buffer *out, uint64_t value)
{
  unsigned char  bytes[9];
  size_t         size = 0;
  int            shift;

  for (shift = 56; shift >= 0; shift -= 8) {
    unsigned char  byte = (unsigned char)(value >> shift);

    if ((size == 0) && (byte == 0) && (shift != 0)) {
      continue;
    }

    if ((size == 0) && (byte & 0x80)) {
      bytes[size++] = 0;
    }

    bytes[size++] = byte;
  }

  put_tlv (out, 0x02, bytes, size);
}

static void
wrap (struct buffer *out, unsigned char tag, struct buffer *inner)
{
  put_tlv (out, tag, inner->data, inner->size);
  free (inner->data);
}

static int
compare_encoded (const void *a, const void *b)
{
  const struct buffer  *left = a;
  const struct buffer  *right = b;
  size_t               size = left->size < right->size ? left->size : right->size;
  int                  order = memcmp (left->data, right->data, size);

  return order != 0 ? order : (left->size > right->size) - (left->size < right->size);
}

static void
put_params (struct buffer *out, const struct param *params, size_t count)
{
  struct buffer  encoded[16];
  struct buffer  set = { 0 };
  size_t         index;

  for (index = 0; index < count; index++) {
    struct buffer  item = { 0 };
    struct buffer  value = { 0 };

    put_integer (&item, params[index].tag);
    if (params[index].tag >> 28 >= 8) {
      put_tlv (&value, 0x04, params[index].bytes, params[index].size);
      wrap (&item, 0xA1, &value);
    } else {
      put_integer (&value, params[index].number);
      wrap (&item, 0xA0, &value);
    }

    encoded[index] = (struct buffer){ 0 };
    wrap (&encoded[index], 0x30, &item);
  }

  qsort (encoded, count, sizeof (encoded[0]), compare_encoded);
  for (index = 0; index < count; index++) {
    put (&set, encoded[index].data, encoded[index].size);
    free (encoded[index].data);
  }

  {
    struct buffer  wrapped = { 0 };

    wrap (&wrapped, 0x31, &set);
    wrap (out, 0xA8, &wrapped);
  }
}

static void
put_explicit_octets (struct buffer *out, unsigned char tag, const void *data, size_t size)
{
  struct buffer  inner = { 0 };

  put_tlv (&inner, 0x04, data, size);
  wrap (out, tag, &inner);
}

static void
put_explicit_integer (struct buffer *out, unsigned char tag, uint64_t value)
{
  struct buffer  inner = { 0 };

  put_integer (&inner, value);
  wrap (out, tag, &inner);
}

static size_t
take (const unsigned char *data, size_t size, unsigned char *tag, const unsigned char **content, size_t *length)
{
  size_t  used = 2;

  if (size < 2) {
    return 0;
  }

  *tag    = data[0];
  *length = data[1];
  if (data[1] & 0x80) {
    size_t  count = data[1] & 0x7F;
    size_t  index;

    if ((count == 0) || (count > 4) || (size < 2 + count)) {
      return 0;
    }

    *length = 0;
    for (index = 0; index < count; index++) {
      *length = *length << 8 | data[2 + index];
    }

    used += count;
  }

  if (*length > size - used) {
    return 0;
  }

  *content = data + used;
  return used + *length;
}

static uint64_t
integer_value (const unsigned char *data, size_t size)
{
  uint64_t  value = size != 0 && (data[0] & 0x80) ? UINT64_MAX : 0;

  while (size-- != 0) {
    value = value << 8 | *data++;
  }

  return value;
}

static int
parse_reply (const unsigned char *data, size_t size, struct reply *out)
{
  const unsigned char  *content;
  size_t               length;
  size_t               used;
  unsigned char        tag;
  int                  index;

  memset (out, 0, sizeof (*out));
  if (!take (data, size, &tag, &content, &length) || (tag != 0x30)) {
    return -1;
  }

  data = content;
  size = length;
  for (index = 0; index < 4; index++) {
    used = take (data, size, &tag, &content, &length);
    if (!used || (tag != 0x02)) {
      return -1;
    }

    if (index == 3) {
      out->err = (long)(int32_t)(uint32_t)integer_value (content, length);
    }

    data += used;
    size -= used;
  }

  while (size != 0) {
    const unsigned char  *inner;
    size_t               inner_length;
    unsigned char        inner_tag;

    used = take (data, size, &tag, &content, &length);
    if (!used) {
      return -1;
    }

    if (((tag == 0xA1) || (tag == 0xA2)) && take (content, length, &inner_tag, &inner, &inner_length)) {
      if (tag == 0xA1) {
        out->long0     = integer_value (inner, inner_length);
        out->has_long0 = 1;
      } else {
        out->bin0      = inner;
        out->bin0_size = inner_length;
      }
    } else if (tag == 0xA5) {
      while (length != 0) {
        size_t  line = take (content, length, &inner_tag, &inner, &inner_length);

        if (!line) {
          break;
        }

        if (out->err != 0) {
          fprintf (stderr, "  ta: %.*s\n", (int)strnlen ((const char *)inner, inner_length), inner);
        }

        content += line;
        length  -= line;
      }
    }

    data += used;
    size -= used;
  }

  return 0;
}

static void
qsee_write (size_t size, size_t reply_max, int32_t *status)
{
  ssize_t  got;

  if (write (qsee, frame, size) != (ssize_t)size) {
    fail ("write " QSEE_DEVICE);
  }

  got = read (qsee, answer, reply_max);
  if (got < 4) {
    fail ("read " QSEE_DEVICE);
  }

  memcpy (status, answer, 4);
}

static void
start_ta (void)
{
  uint32_t  is64 = 1;
  int32_t   status;

  qsee = open (QSEE_DEVICE, O_RDWR | O_CLOEXEC);
  if (qsee < 0) {
    fail ("open " QSEE_DEVICE " (load user_qsee.ko)");
  }

  frame[0] = 'S';
  memcpy (frame + 1, &is64, 4);
  memcpy (frame + 5, TA_NAME, strlen (TA_NAME));
  qsee_write (5 + strlen (TA_NAME), 4 + 256, &status);
  if (status != 0) {
    fprintf (stderr, "unlock_data: starting " TA_NAME ": %d\n", status);
    exit (1);
  }
}

static void
stop_ta (void)
{
  int32_t  status;

  frame[0] = 'X';
  frame[1] = 0;
  qsee_write (2, 4, &status);
  close (qsee);
}

static void
command (uint32_t cmd, struct buffer *fields, struct reply *out)
{
  struct buffer  body = { 0 };
  struct buffer  request = { 0 };
  uint64_t       length;
  uint32_t       want = FRAME;
  int32_t        status;

  put_integer (&body, 3);
  put_integer (&body, 100);
  put_integer (&body, cmd);
  put_integer (&body, (uint64_t)getpid ());
  put (&body, fields->data, fields->size);
  free (fields->data);
  wrap (&request, 0x30, &body);
  if (request.size > FRAME - 8) {
    fail ("request too large");
  }

  frame[0] = 'C';
  memcpy (frame + 1, &want, 4);
  length = request.size;
  memcpy (frame + 5, &length, 8);
  memcpy (frame + 13, request.data, request.size);
  memset (frame + 13 + request.size, 0, FRAME - 8 - request.size);
  explicit_bzero (request.data, request.size);
  free (request.data);
  qsee_write (5 + FRAME, 4 + FRAME, &status);
  explicit_bzero (frame, sizeof (frame));
  memcpy (&length, answer + 4, 8);
  if ((status != 0) || (length > FRAME - 8) || (parse_reply (answer + 12, length, out) != 0)) {
    fprintf (stderr, "unlock_data: command %u: status %d\n", cmd, status);
    exit (1);
  }

  if (out->err != 0) {
    fprintf (stderr, "unlock_data: command %u: KeyMint error %ld\n", cmd, out->err);
    exit (1);
  }
}

static void
configure (void)
{
  struct buffer  fields = { 0 };
  struct reply   out;
  struct param   params[] = {
    NUMBER (TAG_SEC_OS_VERSION, os_version), NUMBER (TAG_SEC_OS_PATCH, os_patch),
    NUMBER (TAG_SEC_VENDOR, vendor_patch),   NUMBER (TAG_OS_VERSION, os_version),
    NUMBER (TAG_OS_PATCH, os_patch),         NUMBER (TAG_VENDOR_PATCH, vendor_patch)
  };

  put_explicit_octets (&fields, 0xA3, "user", 4);
  put_params (&fields, params, sizeof (params) / sizeof (params[0]));
  command (KM_CONFIGURE, &fields, &out);
}

static const uint64_t  sha512_k[80] = {
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
  0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
  0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
  0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
  0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
  0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
  0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
  0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
  0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
  0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
  0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
  0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
  0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

#define ROTR(x, n)  ((x) >> (n) | (x) << (64 - (n)))

static uint64_t
load64 (const unsigned char *bytes)
{
  uint64_t  value = 0;
  int       index;

  for (index = 0; index < 8; index++) {
    value = value << 8 | bytes[index];
  }

  return value;
}

static void
sha512_block (uint64_t *state, const unsigned char *block)
{
  uint64_t  w[80];
  uint64_t  v[8];
  int       i;

  for (i = 0; i < 16; i++) {
    w[i] = load64 (block + 8 * i);
  }

  for (i = 16; i < 80; i++) {
    uint64_t  s0 = ROTR (w[i - 15], 1) ^ ROTR (w[i - 15], 8) ^ (w[i - 15] >> 7);
    uint64_t  s1 = ROTR (w[i - 2], 19) ^ ROTR (w[i - 2], 61) ^ (w[i - 2] >> 6);

    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  memcpy (v, state, sizeof (v));
  for (i = 0; i < 80; i++) {
    uint64_t  t1 = v[7] + (ROTR (v[4], 14) ^ ROTR (v[4], 18) ^ ROTR (v[4], 41)) + ((v[4] & v[5]) ^ (~v[4] & v[6])) +
                   sha512_k[i] + w[i];
    uint64_t  t2 = (ROTR (v[0], 28) ^ ROTR (v[0], 34) ^ ROTR (v[0], 39)) + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));

    memmove (v + 1, v, 7 * sizeof (v[0]));
    v[4] += t1;
    v[0]  = t1 + t2;
  }

  for (i = 0; i < 8; i++) {
    state[i] += v[i];
  }
}

static void
sha512 (const unsigned char *data, size_t size, unsigned char *digest)
{
  uint64_t       state[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
  };
  unsigned char  tail[256] = { 0 };
  size_t         full = size / 128 * 128;
  size_t         rest = size - full;
  size_t         blocks;
  size_t         index;

  for (index = 0; index < full; index += 128) {
    sha512_block (state, data + index);
  }

  memcpy (tail, data + full, rest);
  tail[rest] = 0x80;
  blocks     = rest < 112 ? 1 : 2;
  for (index = 0; index < 8; index++) {
    tail[blocks * 128 - 1 - index] = (unsigned char)((uint64_t)size * 8 >> (8 * index));
  }

  for (index = 0; index < blocks; index++) {
    sha512_block (state, tail + 128 * index);
  }

  for (index = 0; index < 64; index++) {
    digest[index] = (unsigned char)(state[index / 8] >> (56 - 8 * (index % 8)));
  }
}

static unsigned char *
read_file (const char *dir, const char *name, size_t *size)
{
  char           path[512];
  unsigned char  *data = malloc (MAX_FILE);
  ssize_t        got;
  int            fd;

  snprintf (path, sizeof (path), "%s/%s", dir, name);
  fd = open (path, O_RDONLY | O_CLOEXEC);
  if ((fd < 0) || (data == NULL) || ((got = read (fd, data, MAX_FILE)) < 0) || (got == MAX_FILE)) {
    fprintf (stderr, "unlock_data: %s: %s\n", path, strerror (errno));
    exit (1);
  }

  close (fd);
  *size = (size_t)got;
  return data;
}

static void
decrypt_key (const char *dir, unsigned char *key)
{
  unsigned char  app_id[64];
  unsigned char  *prefixed;
  unsigned char  *blob;
  unsigned char  *secdiscardable;
  unsigned char  *encrypted;
  size_t         blob_size;
  size_t         secdiscardable_size;
  size_t         encrypted_size;
  size_t         got = 0;
  struct buffer  fields = { 0 };
  struct reply   out;
  uint64_t       handle;
  struct timespec  now;

  blob           = read_file (dir, "keymaster_key_blob", &blob_size);
  secdiscardable = read_file (dir, "secdiscardable", &secdiscardable_size);
  encrypted      = read_file (dir, "encrypted_key", &encrypted_size);
  if (encrypted_size != GCM_NONCE + KEY_SIZE + GCM_TAG) {
    fail ("encrypted_key is not a 64-byte key");
  }

  prefixed = calloc (1, 128 + secdiscardable_size);
  memcpy (prefixed, SECDISCARDABLE, strlen (SECDISCARDABLE));
  memcpy (prefixed + 128, secdiscardable, secdiscardable_size);
  sha512 (prefixed, 128 + secdiscardable_size, app_id);
  free (prefixed);
  clock_gettime (CLOCK_REALTIME, &now);
  {
    struct param  params[] = {
      NUMBER (TAG_BLOCK_MODE, 32),                    NUMBER (TAG_MAC_LENGTH, 128),
      NUMBER (TAG_PADDING, 1),                        BYTES (TAG_APPLICATION_ID, app_id, sizeof (app_id)),
      BYTES (TAG_NONCE, encrypted, GCM_NONCE),
      NUMBER (TAG_NOW, (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000)
    };

    put_explicit_integer (&fields, 0xA0, 1);
    put_explicit_octets (&fields, 0xA6, blob, blob_size);
    put_params (&fields, params, sizeof (params) / sizeof (params[0]));
  }

  command (KM_BEGIN, &fields, &out);
  if (!out.has_long0) {
    fail ("begin returned no operation handle");
  }

  handle = out.long0;
  fields = (struct buffer){ 0 };
  put_explicit_integer (&fields, 0xA1, handle);
  put_explicit_octets (&fields, 0xA3, encrypted + GCM_NONCE, KEY_SIZE + GCM_TAG);
  command (KM_UPDATE, &fields, &out);
  if (out.bin0_size <= KEY_SIZE) {
    memcpy (key, out.bin0, out.bin0_size);
    got = out.bin0_size;
  }

  explicit_bzero (answer, sizeof (answer));
  fields = (struct buffer){ 0 };
  put_explicit_integer (&fields, 0xA1, handle);
  put_explicit_octets (&fields, 0xA3, "", 0);
  put_explicit_octets (&fields, 0xA4, "", 0);
  command (KM_FINISH, &fields, &out);
  if (got + out.bin0_size == KEY_SIZE) {
    memcpy (key + got, out.bin0, out.bin0_size);
    got = KEY_SIZE;
  }

  explicit_bzero (answer, sizeof (answer));
  free (blob);
  free (secdiscardable);
  free (encrypted);
  if (got != KEY_SIZE) {
    fail ("decrypted key is not 64 bytes");
  }
}

static void
create_mapping (const char *device, const char *name, const unsigned char *key)
{
  struct dm_target  target = { 0, 0, "default-key", NULL };
  char              params[256];
  struct stat       info;
  uint64_t          bytes;
  dev_t             mapping;
  int               block;
  int               index;
  int               result;

  block = open (device, O_RDONLY | O_CLOEXEC);
  if ((block < 0) || (ioctl (block, BLKGETSIZE64, &bytes) != 0) || (fstat (block, &info) != 0)) {
    fail ("open the userdata device");
  }

  close (block);
  index = sprintf (params, "aes-xts-plain64 ");
  for (int i = 0; i < KEY_SIZE; i++) {
    index += sprintf (params + index, "%02x", key[i]);
  }

  sprintf (params + index, " 0 %u:%u 0 " DM_OPTIONS, major (info.st_rdev), minor (info.st_rdev));
  target.sectors = bytes / 512;
  target.params  = params;
  result         = dm_create (name, &target, 1, read_only, &mapping);
  explicit_bzero (params, sizeof (params));
  if (result != 0) {
    exit (1);
  }

  printf ("/dev/mapper/%s %u:%u, %llu sectors\n", name, major (mapping), minor (mapping),
          (unsigned long long)target.sectors);
}

static void
add_fbe_key (const char *mountpoint, const unsigned char *key)
{
  union {
    struct fscrypt_add_key_arg    arg;
    unsigned char                 raw[sizeof (struct fscrypt_add_key_arg) + KEY_SIZE];
  }       request;
  int     fd = open (mountpoint, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  int     result;
  int     index;

  if (fd < 0) {
    fail ("open the mount point");
  }

  memset (&request, 0, sizeof (request));
  request.arg.key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
  request.arg.raw_size      = KEY_SIZE;
  memcpy (request.arg.raw, key, KEY_SIZE);
  result = ioctl (fd, FS_IOC_ADD_ENCRYPTION_KEY, &request.arg);
  explicit_bzero (request.arg.raw, KEY_SIZE);
  if (result != 0) {
    fprintf (stderr, "unlock_data: FS_IOC_ADD_ENCRYPTION_KEY: %s\n", strerror (errno));
    exit (1);
  }

  close (fd);
  printf ("key identifier ");
  for (index = 0; index < FSCRYPT_KEY_IDENTIFIER_SIZE; index++) {
    printf ("%02x", request.arg.key_spec.u.identifier[index]);
  }

  printf ("\n");
}

int
main (int argc, char **argv)
{
  unsigned char  key[KEY_SIZE];
  int            option;

  while ((option = getopt (argc, argv, "rv:p:V:")) != -1) {
    if (option == 'r') {
      read_only = 1;
    } else if (option == 'v') {
      os_version = strtoul (optarg, NULL, 10);
    } else if (option == 'p') {
      os_patch = strtoul (optarg, NULL, 10);
    } else if (option == 'V') {
      vendor_patch = strtoul (optarg, NULL, 10);
    } else {
      return 2;
    }
  }

  if ((os_version == 0) || (os_patch == 0) || (vendor_patch == 0) ||
      (((argc - optind != 4) || (strcmp (argv[optind], "metadata") != 0)) &&
       ((argc - optind != 3) || (strcmp (argv[optind], "fbe") != 0))))
  {
    fprintf (stderr, "usage: unlock_data [-r] -v OS_VERSION -p OS_PATCH -V VENDOR_PATCH metadata KEYDIR DEVICE NAME\n"
                     "       unlock_data [...] fbe KEYDIR MOUNTPOINT\n"
                     "  decrypts a vold key with Samsung's KeyMint TA through " QSEE_DEVICE ", then creates the\n"
                     "  dm-default-key mapping /dev/mapper/NAME (-r: read-only) or adds the key to MOUNTPOINT's filesystem\n");
    return 2;
  }

  start_ta ();
  configure ();
  decrypt_key (argv[optind + 1], key);
  stop_ta ();
  if (strcmp (argv[optind], "metadata") == 0) {
    create_mapping (argv[optind + 2], argv[optind + 3], key);
  } else {
    add_fbe_key (argv[optind + 2], key);
  }

  explicit_bzero (key, sizeof (key));
  return 0;
}
