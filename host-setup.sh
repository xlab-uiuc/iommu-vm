#!/bin/bash

sudo mst start
sudo bash -c "echo 4 > /sys/class/net/enp101s0f1np1/device/sriov_numvfs"
echo "lspci"
sudo lspci -D | grep Mellanox

sudo ifconfig enp101s0f1np1 mtu 4000

echo "detach device"
sudo virsh nodedev-detach pci_0000_65_00_6
