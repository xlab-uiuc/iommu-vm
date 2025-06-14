#!/bin/bash

# --- Configuration ---
QEMU_BIN="/home/saksham/viommu/nested-translation/qemu/build/qemu-system-x86_64"
BIOS_PATH="/home/saksham/viommu/nested-translation/qemu/pc-bios/bios-256k.bin"
KERNEL_PATH="/boot/vmlinuz-6.12.9-iommufd"
INITRD_PATH="/boot/initrd.img-6.12.9-iommufd"
DISK_IMG="/home/saksham/viommu/iommu-vm/server.qcow2"
KERNEL_CMDLINE="root=/dev/vda2 ro console=ttyS0,115200 earlyprintk=serial,ttyS0,115200 intel_iommu=on,sm_on iommu.strict=1"

# Host PCI device for passthrough
VFIO_HOST_PCI_ADDR="0000:65:00.6" # Make sure this is just 65:00.6 for QEMU argument
QEMU_VFIO_HOST_ADDR="65:00.6"

# VM MAC Address
VM_MAC="52:54:00:14:26:e2"

# --- QEMU Command ---
sudo "$QEMU_BIN" \
    -name "server-iommufd-viommu-direct" \
    -machine type=q35,kernel_irqchip=split \
    -cpu host \
    -smp 16 \
    -m 10G \
    -enable-kvm \
    \
    -object memory-backend-ram,id=ram-node0,size=10G \
    -numa node,nodeid=0,cpus=0-15,memdev=ram-node0 \
    \
    -bios "$BIOS_PATH" \
    -kernel "$KERNEL_PATH" \
    -initrd "$INITRD_PATH" \
    -append "$KERNEL_CMDLINE" \
    \
    # PCIe Root Ports (mimicking libvirt's pci.1, pci.4, pci.8)
    # pci.1 for Network (on host 00:02.0)
    -device pcie-root-port,port=0x10,chassis=1,id=pci.1,bus=pcie.0,multifunction=on,addr=0x2.0 \
    # pci.4 for Disk (on host 00:02.3)
    -device pcie-root-port,port=0x13,chassis=4,id=pci.4,bus=pcie.0,addr=0x2.3 \
    # pci.8 for VFIO passthrough device (on host 00:02.7)
    -device pcie-root-port,port=0x17,chassis=8,id=pci.8,bus=pcie.0,addr=0x2.7 \
    \
    # Disk
    -drive file="$DISK_IMG",id=hd0,format=qcow2,if=none,discard=unmap \
    -device virtio-blk-pci,drive=hd0,id=virtio-disk0,bus=pci.4,addr=0x0 \
    \
    # Network (user-mode, simple. For bridge, use -netdev tap,...)
    -netdev user,id=net0,hostfwd=tcp::2222-:22 \
    -device virtio-net-pci,netdev=net0,mac="$VM_MAC",bus=pci.1,addr=0x0 \
    \
    # IOMMU and VFIO specific arguments from your <qemu:commandline>
    -object iommufd,id=iommufd0 \
    -device intel-iommu,intremap=on,caching-mode=on,x-scalable-mode=on,x-flts=on \
    -device "vfio-pci,host=$QEMU_VFIO_HOST_ADDR,id=hostdev0,bus=pci.8,addr=0x0.0,iommufd=iommufd0" \
    \
    # Standard Devices
    -vga virtio \
    -display gtk,gl=off \
    -usb \
    -device usb-tablet \
    -serial stdio \
    -monitor pty \
    -no-hpet \
    \
    # Optional: Add other devices from your XML if needed, e.g.:
    # RNG Device (ensure pci.6 pcie-root-port is created if using specific bus)
    # -object rng-random,id=rngdev0,filename=/dev/urandom \
    # -device pcie-root-port,port=0x15,chassis=6,id=pci.6,bus=pcie.0,addr=0x2.5 \
    # -device virtio-rng-pci,rng=rngdev0,id=rng0,bus=pci.6,addr=0x0 \
    #
    # Memballoon (ensure pci.5 pcie-root-port is created if using specific bus)
    # -device pcie-root-port,port=0x14,chassis=5,id=pci.5,bus=pcie.0,addr=0x2.4 \
    # -device virtio-balloon-pci,id=balloon0,bus=pci.5,addr=0x0
