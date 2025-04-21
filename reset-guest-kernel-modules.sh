#!/bin/bash

set -x 
# sync kernel modules compiled on host with guest

# kernel_name=$(uname -r)
kernel_name="6.12.9-debug"
guest_IP="192.168.123.53"


tar czf modules.tar.gz -C /lib/modules/${kernel_name} .

scp modules.tar.gz schai@${guest_IP}:/tmp/

ssh schai@${guest_IP} "sudo tar xzf /tmp/modules.tar.gz -C /lib/modules/${kernel_name}/ && sudo depmod -a"