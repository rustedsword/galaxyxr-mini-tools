# map_super

Maps logical partitions of Android's `super` read-only with
device-mapper. Runs on the headset, as root.

```
map_super SUPER NAME...
```

`map_super` reads slot 0 of the LP metadata of a non-A/B `super` and
maps each NAME as `/dev/mapper/NAME` from its extents: `linear` on
SUPER or `zero`, up to 32. Requires devtmpfs mounted on `/dev`;
udev is optional.

```
map_super /dev/disk/by-partlabel/super vendor
mount -t ext4 -o ro /dev/mapper/vendor /vendor
```
