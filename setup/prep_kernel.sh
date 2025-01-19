#!/usr/bin/env bash


wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.9.tar.xz
tar -xf linux-6.12.9.tar.xz
cp ubuntu-6.12.9-config linux-6.12.9/.config
cd linux-6.12.9/

make olddefconfig

echo "compilation begins"
make -j 32 LOCALVERSION=-vanilla

sudo make modules_install -j`nproc` INSTALL_MOD_STRIP=1
sudo make install