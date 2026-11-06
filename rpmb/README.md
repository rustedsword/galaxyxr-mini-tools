# rpmb

Reads the UFS RPMB: its write counter or its data. Runs on the
headset, as root.

```
rpmb [-d DEVICE] counter
rpmb [-d DEVICE] [-o FILE] read [ADDRESS [COUNT]]
```

`read` takes 256-byte blocks, by default all 16 MiB. `rpmb` finds the
SCSI generic node of the RPMB well-known LUN (`/dev/sg1`), the unit's
size and the blocks per command (64) in sysfs; `-d` names the node
instead. It only sends read requests (0002h, 0004h): they need no key
and leave the write counter alone. Without the key the MACs can't be
checked.
