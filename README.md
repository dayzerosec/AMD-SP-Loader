# AMD-SP/PSP Loader 
Author: **dayzerosec**

_Loader for AMD-SP or PSP firmware binaries._

![](https://i.imgur.com/MH9C1hu.png)

## Description

Binary Ninja loader for AMD Secure Processor (SP) / Platform Security Processor (PSP) firmware binaries. It will try to load AGESA Bootloader (ABL) and Bootloader blobs and will setup the correct load addresses.

The ABL loader will also optionally annotate syscalls using the dictionary in [./data/syscalls.json](./data/syscalls.json).

## Installation

To install this plugin, go to Binary Ninja's plugin directory (can be found by going to Tools -> "Open Plugin Folder"), and run the following command:

```
git clone https://github.com/Cryptogenic/AMD-SP-Loader
```

Note you'll probably need to restart Binary Ninja for the plugin to load.

## Usage

This loader is intended to be used with binaries extracted via [PSPTool](https://github.com/PSPReverse/PSPTool), as this loader will **not extract firmware from UEFI or perform any decompression before loading**.

Simply load an `ABL*` or `PSP_FW_BOOTLOADER_*` binary to use the loader. Your view name on the top left of the disassembly pane should have an `AMD-SP` prefix. If your particular firmware blob doesn't load and/or loads at an incorrect address, please file an issue.

## Future Work / Places for Contribution

- [ ] Currently load addresses are static, perhaps this should be reworked to dynamically determine it via parsing entrypoint instructions?
- [ ] Add loaders for other firmwares
  - [ ] SMU (xtensa)
  - [ ] Trusted OS (tOS)
  - [ ] Boot time trustlets
- [ ] Reverse and add more syscalls to the annotation dictionary
  - [ ] Update args of existing syscalls
- [ ] Improve annotations to fix-up syscalls in HLIL

## Notes

- The loaders make some assumptions on the load address and such, so its possible a particular binary differs and won't load properly (open an issue).
- Syscall annotations that are prefixed with a `_` are unofficial/guessed.

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:
 * release - 3.2.3814

## Resources

- [https://github.com/PSPReverse](https://github.com/PSPReverse)
- [https://doc.coreboot.org/soc/amd/psp_integration.html](https://doc.coreboot.org/soc/amd/psp_integration.html)
- [https://github.com/sameershaik/coreboot_beagle-xM/blob/main/src/vendorcode/amd/fsp/cezanne/include/bl_uapp/bl_syscall_public.h](https://github.com/sameershaik/coreboot_beagle-xM/blob/main/src/vendorcode/amd/fsp/cezanne/include/bl_uapp/bl_syscall_public.h)

## License

This plugin is released under a [MIT](LICENSE) license.

## Thanks
- PSPReverse for previous work and awesome resources.
- Carstein (inspiration and reference for syscall annotation via [Syscaller](https://github.com/carstein/Syscaller).
