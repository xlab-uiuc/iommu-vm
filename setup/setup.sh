#!/usr/bin/env bash

set -euo pipefail

./install_dependency.sh

# setup virsh
# sudo virt-install \
#     --virt-type=kvm \
#     --name "network-server" \
#     --ram 245760 \
#     --vcpus=80 \
#     --os-variant=ubuntu22.04 \
#     --hvm \
#     --cdrom=$(realpath ubuntu2204.iso)\
#     --network=default,model=virtio \
#     --graphics vnc \
#     --disk path=/data/server.qcow2,size=256,bus=virtio,format=qcow2
VM="network-server"

# sudo virsh define $VM.xml


setup_bridge () {
    # sudo ip link delete bridge_vm type bridge
    local bridge_name="bridge_vm"
    sudo ip link add name $bridge_name type bridge
    sudo ip link set enp202s0f0np0 master $bridge_name

    # get from ip address show enp202s0f0np0
    IP="10.10.1.2/24"
    sudo ip address add $IP dev bridge_vm
}


# bridge_vm network config
# <interface type='bridge'>
#     <mac address='52:54:00:ba:6d:b5'/>
#     <source bridge='bridge_vm'/>
#     <model type='virtio'/>
#     <address type='pci' domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>
# </interface>

# install mft

install_mft () {
    mkdir -p mft
    cd mft
    wget https://www.mellanox.com/downloads/MFT/mft-4.30.1-8-x86_64-deb.tgz
    tar xzvf mft-4.30.1-8-x86_64-deb.tgz
    cd mft-4.30.1-8-x86_64-deb/
    sudo ./install.sh
    sudo mst start

    # expected output
# schai@node-3:~/linux-6.12.9$ sudo mst status
# MST modules:
# ------------
#     MST PCI module is not loaded
#     MST PCI configuration module loaded

# MST devices:
# ------------
# /dev/mst/mt4119_pciconf0         - PCI configuration cycles access.
#                                    domain:bus:dev.fn=0000:31:00.0 addr.reg=88 data.reg=92 cr_bar.gw_offset=-1
#                                    Chip revision is: 00 
    # (eno12399np0)
# /dev/mst/mt4125_pciconf0         - PCI configuration cycles access.
#                                    domain:bus:dev.fn=0000:ca:00.0 addr.reg=88 data.reg=92 cr_bar.gw_offset=-1
#                                    Chip revision is: 00
# enp202s0f0np0
}

install_ofed () {
    wget https://content.mellanox.com/ofed/MLNX_OFED-24.10-1.1.4.0/MLNX_OFED_LINUX-24.10-1.1.4.0-ubuntu22.04-x86_64.iso
    sudo mkdir -p /mnt
    sudo mount -o ro,loop MLNX_OFED_LINUX-24.10-1.1.4.0-ubuntu22.04-x86_64.iso /mnt
    cd /mnt
    ./mlnxofedinstall --without-dkms --add-kernel-support --kernel `uname -r` --without-fw-update --force
}

prepare_kernel () {
    cd ~
    wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.9.tar.xz
    tar -xf linux-6.12.9.tar.xz
    cp iommu-vm/ubuntu-6.12.9-config linux-6.12.9/.config
    cd linux-6.12.9/
    
    make olddefconfig
    
    echo "compilation begins"
    make -j 32 LOCALVERSION=-vanilla

    sudo make modules_install -j`nproc` INSTALL_MOD_STRIP=1
    sudo make install
}

