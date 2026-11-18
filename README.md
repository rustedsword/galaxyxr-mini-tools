# galaxyxr_mini_tools

Small tools for the Samsung Galaxy XR.

| Tool | Runs on | Does |
|---|---|---|
| [`bdf_mac`](bdf_mac/README.md) | anywhere | writes an ath12k `board-2.bin` for the WCN7850 with the factory MAC |
| [`bt_nvm`](bt_nvm/README.md) | anywhere | writes a Bluetooth NVM for the WCN7850 with Samsung's XML overrides and the factory address |
| [`map_super`](map_super/README.md) | headset, as root | maps logical partitions of Android's `super` with device-mapper |
| [`mount_android_userdata`](mount_android_userdata/README.md) | headset, as root | mounts Android's encrypted `/data` |
| [`panels_off`](panels_off/README.md) | headset, as root | switches off the panels: every active CRTC of the DRM devices |
| [`rpmb`](rpmb/README.md) | headset, as root | reads the UFS RPMB: its write counter or its data |
| [`uefivars`](uefivars/README.md) | anywhere | lists the UEFI variables in a dump of the RPMB or of `uefivarstore` |
| [`unlock_data`](unlock_data/README.md) | headset, as root | unlocks Android's encrypted `/data` with Samsung's KeyMint TA |

## Build

C23 and CMake: GCC 15, or clang 19 or later. `bt_nvm` needs libxml2.

```
cmake -S . -B build -G Ninja
ninja -C build
```
