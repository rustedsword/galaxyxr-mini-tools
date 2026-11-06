# uefivars

Lists the UEFI variables in a dump of the RPMB or of `uefivarstore`.
Runs anywhere.

```
sudo rpmb read | uefivars -
uefivars [-x] rpmb.bin
```

`-x` dumps all of each variable's data, not just its first 16 bytes.

uefisecapp (`qcom.tz.uefisecapp`) answers UEFI's variable calls until
ExitBootServices, when VariableDxe shuts it down; loaded again, it
refuses every call. Its tables are plain data, so `uefivars` reads
them from storage. On a fused headset they live in the RPMB,
partitions 2, 3 and 4 of owner `0d1cc64d7916ef87`; the `uefivarstore`
partition only has the factory's copy.

Layout, little endian:

- `PTBL` at offset 0: magic, two `u16`, `u32` sectors in use, `u32`
  count, then 16-byte entries: `u32` id, `u16` first sector, `u16`
  sectors, 8-byte owner. Sectors are 512 bytes in the RPMB, 4096 in
  `uefivarstore`.
- A partition is two halves. Each has a `DStr` header in its first
  sector (`u16` generation at 6, low 2 bits; `u16` data sectors at
  12; `u32` write count at 16; CRC32 of the table at 20; CRC32 of
  bytes 0-39 at 40), the table from the second sector and the header
  again in its last sector. Of two good halves, the one a generation
  ahead wins.
- `VAR2` table: magic, two `u16`, `u32` bytes used, `u32` capacity,
  `u32` attributes of all its variables, then groups: `u32` size and
  the vendor GUID, then records: `u32` size, 8 unused bytes, `u32`
  data size, `u16` name size, UTF-16 name, data aligned to 4 bytes.
