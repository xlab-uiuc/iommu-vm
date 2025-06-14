#!/bin/bash

set -x
virsh shutdown server-vIOMMU-debug
sleep 5

virsh define server_vIOMMU_qemu9_debug.xml

virsh start server-vIOMMU-debug