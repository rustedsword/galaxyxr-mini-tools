# bt_nvm

Writes a Bluetooth NVM for the headset's WCN7850 with the overrides of
Samsung's `bt_nvm_loading.xml` and the factory address. Runs anywhere.

```
bt_nvm NVM XML ADDRESS_FILE OUT
```

The inputs come from the headset: Samsung's NVM
(`/vendor/firmware/hmtnv20.b21`), its overrides
(`/vendor/firmware/bt_nvm_loading.xml`) and the factory address
(`/mnt/vendor/efs/bluetooth/bt_addr`). Android applies the XML and puts
the address in before the download. The mainline kernel downloads the
file as it is, so OUT is the file for it, as `qca/hmtnv20.b21`.

Each `TagN` element of the XML changes the NVM's tag N: `default` sets
the bytes at the listed offsets, `entire` replaces the whole tag. A tag
stays as it is when the XML's `Length` is 0, when the NVM has no such
tag, and when the NVM's tag has another length. On the SM-I610 the XML
sets 270 bytes in 8 tags, among them the transmit power levels, the
channel calibration and the SAR backoff.

The address goes into tag 2, lowest byte first. The kernel takes it for
the NVM's default address, which every device has, and asks for another
one unless the Bluetooth node of the device tree has
`qcom,nvm-bd-address-valid`.
