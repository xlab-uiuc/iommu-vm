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

sudo virsh define $VM.xml


setup_bridge () {
    # sudo ip link delete bridge_vm type bridge
    local bridge_name="bridge_vm"
    sudo ip link add name $bridge_name type bridge
    sudo ip link set enp202s0f0np0 master $bridge_name

    # get from ip address show enp202s0f0np0
    IP="10.10.1.2/24"
    sudo ip address add $IP dev bridge_vm
}