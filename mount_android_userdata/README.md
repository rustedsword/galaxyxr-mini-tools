# mount_android_userdata

Mounts Android's encrypted `/data`. Runs on the headset, as root.

```
mount_android_userdata [-r] MOUNTPOINT
```

`mount_android_userdata` finds the partitions by name, which must be
unique, waiting up to ten seconds for each, and

- reads KeyMint's OS version and patch levels from the properties of
  `vbmeta`;
- starts the `skeymast` TA through `/dev/qsee`, which decrypts the vold
  keys below;
- maps `userdata` as `/dev/mapper/userdata` with `dm-default-key`
  (`aes-xts-plain64`, 4 KiB sectors) and the key in
  `vold/metadata_encryption/key` of `metadata`, or reuses that mapping
  when it exists in the same mode;
- mounts it as f2fs with `noatime,nosuid,nodev,inlinecrypt` and adds
  the keys of file-based encryption: `unencrypted/key` and, best
  effort, the DE key of each user in `misc/vold/user_keys/de`;
- moves the mount to MOUNTPOINT.

`-r` maps read-only and mounts with `ro,norecovery`: nothing is
written. A failure leaves nothing mounted. `umount` leaves the
mapping: `dmsetup remove userdata` removes it.
Directories under the users' CE keys stay locked.

Requires `user_qsee.ko` loaded, `skeymast` where the kernel looks for
firmware, and devtmpfs mounted on `/dev`; udev is optional.

Rebuild any initramfs containing `mount_android_userdata` after
updating the tool.
