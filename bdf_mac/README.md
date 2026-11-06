# bdf_mac

Writes an ath12k `board-2.bin` for the headset's WCN7850 with its
factory MAC. Runs anywhere.

```
bdf_mac BDWLAN REGDB MAC_FILE OUT
```

The inputs come from the headset: Samsung's board data
(`/vendor/firmware/kiwi/bdwlan.elf`), its regdb
(`/vendor/firmware/kiwi/regdb.bin`) and the factory MAC
(`/mnt/vendor/efs/wifi/.mac.info`). `bdf_mac` puts the MAC into the
board data segment (MAC at 0x0e, use-board-MAC flag at 0x1e, XOR
checksum at 0x0a), seals the board data and the regdb with the
HMAC-SHA256 trailer the upstream firmware checks, and stores them
under the names ath12k asks for: the board data as
`bus=pci,vendor=17cb,device=1107,subsystem-vendor=17cb,subsystem-device=1107,qmi-chip-id=2,qmi-board-id=255`,
with and without `,variant=Samsung_Galaxy_XR`, the regdb as
`bus=pci`. OUT goes to `/lib/firmware/ath12k/WCN7850/hw2.0/board-2.bin`.
