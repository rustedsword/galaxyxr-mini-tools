#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <drm/drm.h>
#include <drm/drm_mode.h>

#define MAX_CRTCS  16

static int
panels_off (const char *path)
{
  struct drm_mode_card_res  resources;
  uint32_t                  crtcs[MAX_CRTCS];
  int                       active = 0;
  int                       fd;

  fd = open (path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    fprintf (stderr, "panels_off: %s: %s\n", path, strerror (errno));
    return -1;
  }

  memset (&resources, 0, sizeof (resources));
  if ((ioctl (fd, DRM_IOCTL_MODE_GETRESOURCES, &resources) != 0) || (resources.count_crtcs > MAX_CRTCS)) {
    fprintf (stderr, "panels_off: %s: no KMS resources\n", path);
    close (fd);
    return -1;
  }

  resources = (struct drm_mode_card_res){ .crtc_id_ptr = (uintptr_t)crtcs, .count_crtcs = resources.count_crtcs };
  if (ioctl (fd, DRM_IOCTL_MODE_GETRESOURCES, &resources) != 0) {
    fprintf (stderr, "panels_off: %s: CRTC list: %s\n", path, strerror (errno));
    close (fd);
    return -1;
  }

  for (uint32_t index = 0; index < resources.count_crtcs; index++) {
    struct drm_mode_crtc  crtc = { .crtc_id = crtcs[index] };

    if ((ioctl (fd, DRM_IOCTL_MODE_GETCRTC, &crtc) != 0) || !crtc.mode_valid) {
      continue;
    }

    crtc = (struct drm_mode_crtc){ .crtc_id = crtcs[index] };
    if (ioctl (fd, DRM_IOCTL_MODE_SETCRTC, &crtc) != 0) {
      fprintf (stderr, "panels_off: %s: CRTC %u: %s\n", path, crtcs[index], strerror (errno));
      close (fd);
      return -1;
    }

    active++;
  }

  close (fd);
  printf ("%s: %d of %u CRTCs switched off\n", path, active, resources.count_crtcs);
  return 0;
}

int
main (int argc, char **argv)
{
  int  status = 0;

  if (argc < 2) {
    fprintf (stderr, "usage: panels_off CARD...\n  switches off every active CRTC of the DRM devices\n");
    return 2;
  }

  for (int index = 1; index < argc; index++) {
    status |= panels_off (argv[index]) != 0;
  }

  return status;
}
