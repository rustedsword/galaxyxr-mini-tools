# panels_off

Switches off the panels: every active CRTC of the given DRM devices.
Runs on the headset, as root.

```
panels_off CARD...
```

`panels_off /dev/dri/card*` disables each CRTC that has a mode with
`DRM_IOCTL_MODE_SETCRTC` and no framebuffer. That takes DRM master: it
fails while a compositor holds the card.
