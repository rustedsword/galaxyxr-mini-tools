#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#define TLV_NVM          2
#define TLV_HEADER_SIZE  4
#define TAG_HEADER_SIZE  12
#define TAG_ADDRESS      2
#define ADDRESS_SIZE     6

struct buffer {
  uint8_t  *data;
  size_t   size;
};

struct list {
  unsigned long  *values;
  size_t         count;
};

__attribute__ ((noreturn, format (printf, 1, 2))) static void
fail (const char *format, ...)
{
  va_list  args;

  fputs ("bt_nvm: ", stderr);
  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);
  fputc ('\n', stderr);
  exit (1);
}

static struct buffer
read_file (const char *path)
{
  struct buffer  file = { 0 };
  struct stat    info;
  int            fd;

  fd = open (path, O_RDONLY | O_CLOEXEC);
  if ((fd < 0) || (fstat (fd, &info) != 0) || ((file.data = malloc (info.st_size + 1)) == NULL) ||
      (read (fd, file.data, info.st_size) != info.st_size))
  {
    fail ("cannot read %s", path);
  }

  close (fd);
  file.size = info.st_size;
  return file;
}

static void
write_file (const char *path, const struct buffer *out)
{
  int  fd = open (path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);

  if ((fd < 0) || (write (fd, out->data, out->size) != (ssize_t)out->size) || (close (fd) != 0)) {
    unlink (path);
    fail ("cannot write %s", path);
  }
}

static size_t
tags_end (const struct buffer *nvm)
{
  return TLV_HEADER_SIZE + (nvm->data[1] | nvm->data[2] << 8 | (size_t)nvm->data[3] << 16);
}

static void
check_nvm (const struct buffer *nvm)
{
  size_t  end, offset = TLV_HEADER_SIZE;

  if ((nvm->size < TLV_HEADER_SIZE) || (nvm->data[0] != TLV_NVM) || ((end = tags_end (nvm)) > nvm->size)) {
    fail ("NVM is not a type 2 TLV file");
  }

  while (offset < end) {
    if ((end - offset < TAG_HEADER_SIZE) ||
        ((size_t)(nvm->data[offset + 2] | nvm->data[offset + 3] << 8) > end - offset - TAG_HEADER_SIZE))
    {
      fail ("NVM has a tag that crosses its end");
    }

    offset += TAG_HEADER_SIZE + (nvm->data[offset + 2] | nvm->data[offset + 3] << 8);
  }
}

static uint8_t *
find_tag (const struct buffer *nvm, unsigned long id, size_t *size)
{
  size_t  end = tags_end (nvm);

  for (size_t offset = TLV_HEADER_SIZE; offset < end; offset += TAG_HEADER_SIZE + *size) {
    uint8_t  *tag = nvm->data + offset;

    *size = tag[2] | tag[3] << 8;
    if ((unsigned long)(tag[0] | tag[1] << 8) == id) {
      return tag + TAG_HEADER_SIZE;
    }
  }

  return NULL;
}

static xmlNodePtr
child (xmlNodePtr parent, const char *name)
{
  for (xmlNodePtr node = parent->children; node != NULL; node = node->next) {
    if ((node->type == XML_ELEMENT_NODE) && xmlStrEqual (node->name, BAD_CAST name)) {
      return node;
    }
  }

  return NULL;
}

static bool
attribute (xmlNodePtr node, const char *name, unsigned long *value)
{
  xmlChar  *text = (node != NULL) ? xmlGetProp (node, BAD_CAST name) : NULL;
  char     *end;
  bool     valid;

  if (text == NULL) {
    return false;
  }

  errno  = 0;
  *value = strtoul ((const char *)text, &end, 0);
  valid  = (errno == 0) && (end != (char *)text);
  while (isspace ((unsigned char)*end)) {
    end++;
  }

  valid = valid && (*end == 0);
  xmlFree (text);
  return valid;
}

static void
append (struct list *list, unsigned long value)
{
  list->values = realloc (list->values, (list->count + 1) * sizeof (*list->values));
  if (list->values == NULL) {
    fail ("out of memory");
  }

  list->values[list->count++] = value;
}

/* Either <Name0 value="..."/> children or numbers in the text, split by commas or spaces */
static bool
read_list (xmlNodePtr node, struct list *list)
{
  xmlChar     *text;
  const char  *at;
  bool        valid = true;

  *list = (struct list) { 0 };
  for (xmlNodePtr item = node->children; item != NULL; item = item->next) {
    unsigned long  value;

    if (item->type != XML_ELEMENT_NODE) {
      continue;
    }

    if (!attribute (item, "value", &value)) {
      return false;
    }

    append (list, value);
  }

  if (list->count > 0) {
    return true;
  }

  text = xmlNodeGetContent (node);
  if (text == NULL) {
    return false;
  }

  at = (const char *)text;
  while (valid) {
    unsigned long  value;
    char           *end;

    while (isspace ((unsigned char)*at) || (*at == ',')) {
      at++;
    }

    if (*at == 0) {
      break;
    }

    errno = 0;
    value = strtoul (at, &end, 0);
    valid = (errno == 0) && (end != at) && ((*end == 0) || isspace ((unsigned char)*end) || (*end == ','));
    if (valid) {
      append (list, value);
      at = end;
    }
  }

  xmlFree (text);
  return valid;
}

static bool
read_counted_list (xmlNodePtr tag, const char *name, const char *count_name, struct list *list)
{
  xmlNodePtr     node       = child (tag, name);
  xmlNodePtr     count_node = child (tag, count_name);
  unsigned long  count;

  if ((node == NULL) || !read_list (node, list)) {
    return false;
  }

  return (count_node == NULL) || (attribute (count_node, "count", &count) && (count == list->count));
}

static void
apply_tag (struct buffer *nvm, xmlNodePtr node, unsigned long id)
{
  xmlNodePtr     type_node = child (node, "ChangeType");
  xmlChar        *type     = (type_node != NULL) ? xmlGetProp (type_node, BAD_CAST "type") : NULL;
  struct list    changes, offsets;
  unsigned long  length;
  uint8_t        *data;
  size_t         size;

  if ((type == NULL) || !attribute (child (node, "Length"), "len", &length) || (child (node, "Changes") == NULL)) {
    fail ("XML Tag%lu is incomplete", id);
  }

  /* Qualcomm's loader leaves a tag alone when Length is 0, or isn't the length the NVM has */
  data = find_tag (nvm, id, &size);
  if ((length == 0) || (data == NULL) || (length != size)) {
    xmlFree (type);
    return;
  }

  if (!read_counted_list (node, "Changes", "ChangesCount", &changes)) {
    fail ("XML Tag%lu has invalid changes", id);
  }

  for (size_t i = 0; i < changes.count; i++) {
    if (changes.values[i] > UINT8_MAX) {
      fail ("XML Tag%lu has a change that is not a byte", id);
    }
  }

  if (xmlStrEqual (type, BAD_CAST "entire")) {
    if (changes.count != size) {
      fail ("XML Tag%lu replaces %zu bytes of %zu", id, changes.count, size);
    }

    for (size_t i = 0; i < size; i++) {
      data[i] = changes.values[i];
    }
  } else if (xmlStrEqual (type, BAD_CAST "default")) {
    if (!read_counted_list (node, "Offset", "OffsetCount", &offsets) || (offsets.count != changes.count)) {
      fail ("XML Tag%lu has offsets that don't match its changes", id);
    }

    for (size_t i = 0; i < offsets.count; i++) {
      if (offsets.values[i] >= size) {
        fail ("XML Tag%lu has an offset past the tag's end", id);
      }

      data[offsets.values[i]] = changes.values[i];
    }

    free (offsets.values);
  } else {
    fail ("XML Tag%lu has an unknown change type", id);
  }

  free (changes.values);
  xmlFree (type);
}

static void
set_address (struct buffer *nvm, const char *path)
{
  struct buffer  file = read_file (path);
  uint8_t        address[ADDRESS_SIZE];
  uint8_t        bits = 0;
  uint8_t        *data;
  size_t         size;

  while ((file.size > 0) && ((file.data[file.size - 1] == 0) || isspace (file.data[file.size - 1]))) {
    file.size--;
  }

  if (file.size != 3 * ADDRESS_SIZE - 1) {
    fail ("no address in %s", path);
  }

  for (int i = 0; i < ADDRESS_SIZE; i++) {
    char  hex[3] = { file.data[3 * i], file.data[3 * i + 1], 0 };

    if (!isxdigit ((unsigned char)hex[0]) || !isxdigit ((unsigned char)hex[1]) ||
        ((i < ADDRESS_SIZE - 1) && (file.data[3 * i + 2] != ':')))
    {
      fail ("no address in %s", path);
    }

    address[ADDRESS_SIZE - 1 - i] = strtoul (hex, NULL, 16);
    bits                         |= address[ADDRESS_SIZE - 1 - i];
  }

  data = find_tag (nvm, TAG_ADDRESS, &size);
  if (bits == 0) {
    fail ("the address in %s is zero", path);
  }

  if ((data == NULL) || (size != ADDRESS_SIZE)) {
    fail ("NVM has no address tag");
  }

  memcpy (data, address, ADDRESS_SIZE);
  free (file.data);
}

int
main (int argc, char **argv)
{
  struct buffer  nvm;
  xmlDocPtr      doc;
  xmlNodePtr     root;

  if (argc != 5) {
    fprintf (stderr, "usage: bt_nvm NVM XML ADDRESS_FILE OUT\n"
                     "  writes a Bluetooth NVM for the Galaxy XR's WCN7850: Samsung's NVM\n"
                     "  (/vendor/firmware/hmtnv20.b21) with the overrides of its XML\n"
                     "  (/vendor/firmware/bt_nvm_loading.xml) and the factory address\n"
                     "  (/mnt/vendor/efs/bluetooth/bt_addr), which Android puts in before the download\n");
    return 2;
  }

  nvm = read_file (argv[1]);
  check_nvm (&nvm);

  doc  = xmlReadFile (argv[2], NULL, XML_PARSE_NONET);
  root = (doc != NULL) ? xmlDocGetRootElement (doc) : NULL;
  if ((root == NULL) || !xmlStrEqual (root->name, BAD_CAST "Tag")) {
    fail ("%s is not an XML file with a Tag root", argv[2]);
  }

  for (xmlNodePtr node = root->children; node != NULL; node = node->next) {
    const char     *name = (const char *)node->name;
    char           *end;
    unsigned long  id;

    if ((node->type != XML_ELEMENT_NODE) || (strncmp (name, "Tag", 3) != 0) || !isdigit ((unsigned char)name[3])) {
      continue;
    }

    errno = 0;
    id    = strtoul (name + 3, &end, 10);
    if ((errno != 0) || (*end != 0) || (id > UINT16_MAX)) {
      fail ("XML has an invalid element %s", name);
    }

    apply_tag (&nvm, node, id);
  }

  set_address (&nvm, argv[3]);
  write_file (argv[4], &nvm);
  return 0;
}
