# unlock_data

Unlocks Android's encrypted `/data` with Samsung's KeyMint TA. Runs on
the headset, as root.

```
unlock_data [-r] -v OS_VERSION -p OS_PATCH -V VENDOR_PATCH metadata KEYDIR DEVICE NAME
unlock_data -v OS_VERSION -p OS_PATCH -V VENDOR_PATCH fbe KEYDIR MOUNTPOINT
```

`unlock_data` starts the `skeymast` TA through `/dev/qsee` (load
`user_qsee.ko`), configures it with KeyMint's OS version and patch
levels and has it decrypt the vold key in KEYDIR: `encrypted_key` is
AES-GCM under `keymaster_key_blob`, its application id comes from
`secdiscardable`. Then:

- `metadata` maps DEVICE as `/dev/mapper/NAME` with `dm-default-key`
  (`aes-xts-plain64`, 4 KiB sectors); `-r` makes it read-only.
- `fbe` adds the key to the filesystem at MOUNTPOINT and prints its
  identifier.

XrBoot passes the levels as
`rd.galaxyxr.keymint=OS_VERSION,OS_PATCH,VENDOR_PATCH`. With them in
LEVELS, as `-v … -p … -V …`, the initramfs does:

```
mount -t ext4 -o ro,noload /dev/disk/by-partlabel/metadata /metadata
unlock_data $LEVELS metadata /metadata/vold/metadata_encryption/key \
    /dev/disk/by-partlabel/userdata userdata
mount -t f2fs -o noatime,inlinecrypt /dev/mapper/userdata /data
unlock_data $LEVELS fbe /data/unencrypted/key /data
```

The DE keys of the users, `/data/misc/vold/user_keys/de/N`, go to
`/data` the same way.
