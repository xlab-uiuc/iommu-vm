#!/usr/bin/env bash

# NOTE: The script assumes you are running a deb system

# MST (NVIDIA firmware) download
# https://network.nvidia.com/products/adapter-software/firmware-tools/
# MST installation guide
# https://enterprise-support.nvidia.com/s/article/getting-started-with-mellanox-firmware-tools--mft--for-linux


mkdir -p mft
cd mft
wget https://www.mellanox.com/downloads/MFT/mft-4.30.1-8-x86_64-deb.tgz
tar xzvf mft-4.30.1-8-x86_64-deb.tgz
cd mft-4.30.1-8-x86_64-deb/
sudo ./install.sh
sudo mst start