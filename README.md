# Scorpi - A Modern Lightweight General-Purpose Hypervisor

## Overview

Scorpi is a modern, lightweight, general-purpose hypervisor designed to be an alternative to QEMU.

### Key Features

- **Modern**: Implements only modern devices, primarily VirtIO-based, avoiding legacy emulations.
- **Lightweight**: Built on FreeBSD Bhyve and written in C, with minimal code base for emulating devices.
- **General-Purpose**: Supports headless and graphical VMs, EFI boot loader, and ACPI. Can run  Linux and Windows VMs.
- **Modular**: Designed to be used as an API in other applications and services. Graphics, UI and user input are separate modules, and networking can be modularized as well.

## Platform Support

Currently, Scorpi runs on Mac ARM64 using Apple's Hypervisor Framework. The plan is to expand support to:

- **Linux x86 and ARM** using **KVM**
- **Additional architectures**, including **RISC-V**

## Available Bootloaders

1. **U-Boot** - Fast and compact but lacks some advanced features such as ACPI and graphics. Best used for headless VMs that require fast start.\
   [Source Code](https://github.com/macos-fuse-t/u-boot)

2. **EDK2 UEFI** - Full-featured bootloader that provides ACPI support, frame buffer, and a variety of boot device drivers.\
   [Source Code](https://github.com/macos-fuse-t/edk2)

## Running Linux VMs

1. Download an ISO that supports ARM<sub>64</sub> architecture.
2. Create an empty disk with:
   ```sh
   mkfile -n [size] [img_file]
   ```
3. Example command to start a VM:
   ```sh
   ./builddir/scorpi -s 0,hostbridge -o console=stdio -o bootrom=./firmware/SCORPI_EFI.fd -s 1,xhci -u kbd -u tablet -s 2,virtio-blk,[img_file] -s 3,virtio-blk,[iso_file],ro -s 4,virtio-net,slirp -s 5,virtio-gpu,hdpi=on -m 2G -c 2 -l /tmp/vm_sock vm1
   ```
   To use a graphical viewer, refer to the following reference project: [ScorpiViewer](https://github.com/macos-fuse-t/ScorpiViewer)

## Running a Windows VM

The easiest way to try a Windows 11 VM is to download a Microsoft HyperV preview image and convert it to Scorpi.

1. Download a VHDX image from:\
   [Windows Insider Preview ARM<sub>64</sub>](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewarm64)
2. Convert the disk image to Scorpi format using `qemu-img`:
   ```sh
   qemu-img convert -f vhdx -O raw input.vhdx win11.img
   ```
3. Run Scorpi:
   ```sh
   ./builddir/scorpi -s 0,hostbridge -o bootrom=./firmware/SCORPI_EFI.fd -s 1,xhci -u kbd -u tablet -u net,backend=slirp -s 2,ahci-hd,win11.img -s 3,virtio-gpu,fb=on -l /tmp/vm_sock -c 4 -m 4G vm1
   ```
4. Run ScorpiViewer.

## Future Roadmap

- Implement and add missing features (file sharing, copy/paste support)
- Implement Linux support on top of KVM.
- Add Windows DirectX 12 display driver.
- Extend support to RISC-V and other platforms.

## Releated Projects
[U-Boot bootloader](https://github.com/macos-fuse-t/u-boot)  
[EDK2 bootloader](https://github.com/macos-fuse-t/edk2)  
[Scorpi Viewer](https://github.com/macos-fuse-t/ScorpiViewer)  

## Licensing

Scorpi is released under a **permissive license**, providing flexibility for various use cases.

## Get Involved

Contributions and feedback are welcome! Stay tuned for updates as Scorpi evolves into a powerful and versatile hypervisor.

For inquiries, contact **Alex Fishman** at [alex@fuse-t.org](mailto\:alex@fuse-t.org).

