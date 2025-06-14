#!/usr/bin/env bash

# NOTE: The script assumes you are running ubuntu 20.04

# OFED driver download:
# https://network.nvidia.com/products/infiniband-drivers/linux/mlnx_ofed/
# OFED installation Guide
# https://docs.nvidia.com/networking/display/mlnxofedv461000/installing+mellanox+ofed


wget https://content.mellanox.com/ofed/MLNX_OFED-24.10-1.1.4.0/MLNX_OFED_LINUX-24.10-1.1.4.0-ubuntu20.04-x86_64.iso
sudo mkdir -p /mnt
sudo mount -o ro,loop MLNX_OFED_LINUX-24.10-1.1.4.0-ubuntu20.04-x86_64.iso /mnt
cd /mnt
./mlnxofedinstall --without-dkms --add-kernel-support --kernel `uname -r` --without-fw-update --force \
    --kernel-sources $(realpath ~/linux-6.12.9)
