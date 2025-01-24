#!/usr/bin/env bash

kernel_version="6.0.3"
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${kernel_version}.tar.xz
# wget https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-${kernel_version}.tar.gz
tar -xf linux-${kernel_version}.tar.xz
cp ubuntu-6.12.9-config linux-${kernel_version}/.config
cd linux-${kernel_version}/

make olddefconfig

echo "compilation begins"
make -j 32 LOCALVERSION=-vanilla

sudo make modules_install -j`nproc` INSTALL_MOD_STRIP=1
sudo make install