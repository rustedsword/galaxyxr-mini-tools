# galaxyxr_mini_tools

Small tools for the Samsung Galaxy XR.

| Tool | Runs on | Does |
|---|---|---|
| [`rpmb`](rpmb/README.md) | headset, as root | reads the UFS RPMB: its write counter or its data |
| [`uefivars`](uefivars/README.md) | anywhere | lists the UEFI variables in a dump of the RPMB or of `uefivarstore` |

## Build

C23 and CMake: GCC 15, or clang 19 or later.

```
cmake -S . -B build -G Ninja
ninja -C build
```
