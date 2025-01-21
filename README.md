# IOMMUVM

IO Memory protection mechanisms prevent malicious and/or buggy IO devices. It achieves protection by using IOMMU to translate device addresses to physical addresses. However, recent research has found that providing strict memory protections with IOMMU naively may degrade application’s performance by up to 60% [1]. To provide the strongest safety property (commonly referred as strict mode), immediately after usage of each IO virtual address (IOVA), IOVA will be unmapped and corresponding IOTLB entries will be invalidated. Such operation leads to non trivial performance overhead and may degrade application performance significantly.

The performance impact is exacerbated in virtualized cases since nested IO page table walks are more expensive and frequent VM exits may also happen. Applications like Memcached and nginx may suffer from up to 97% throughput degradation while enforcing strict safety properties [2]. We wish to further explore the root cause of performance degradation in the virtualized and develop techniques to achieve close to native performance.

We plan to first profile application’s performance (Redis, Memacached, nginx) under strict, lazy and passthrough policies. We will need connected servers with CX6 NICs (e.g. r650 or 6525). We will analyze the performance breakdown, and develop OS-hypervisor techniques to make IOPT translation faster or reduce the number of IOTLB invalidations.


[1] Benny Rubin, Saksham Agarwal, Qizhe Cai, and Rachit Agarwal. 2024. Fast &amp; Safe IO Memory Protection. In Proceedings of the ACM SIGOPS 30th Symposium on Operating Systems Principles (SOSP '24). Association for Computing Machinery, New York, NY, USA, 95–109. https://doi.org/10.1145/3694715.3695943

[2] Kun Tian, Yu Zhang, Luwei Kang, Yan Zhao, and Yaozu Dong. 2020. CoIOMMU: a virtual IOMMU with cooperative DMA buffer tracking for efficient memory management in direct I/O. In Proceedings of the 2020 USENIX Conference on Usenix Annual Technical Conference (USENIX ATC'20). USENIX Association, USA, Article 32, 479–492.



# Environment Setup Guideline

## Prerequisite Installation
```bash
# Install package dependencies
./setup/install_dependency.sh
```

## Kernel Preparation

```bash
# Compile and install kernel
./setup/prep_kernel.sh
```
With successful compilation, you should find `vmlinuz-6.12.9-vanilla` under `/boot` folder.

Modify `/etc/default/grub`
and append 
`intel_iommu=on iommu.strict=1`

```bash
# update config
sudo update-grub

# reboot to 6.12.9-vanilla
./reboot-6.12.9.sh
```

## Driver Installation
```bash
# Install mft driver
# NOTE: script assumes debian system
./setup/install_mft.sh

# Install OFED drirver. Require sudo.
# NOTE: scripts assumes ubuntu 22.04
./setup/install_ofed.sh

# If installation is successful, follow the guide to run
sudo /etc/init.d/openibd restart
```

## Host Setup
1. Check interface information
```bash
# Find bus information from interface
# Interface name can be acquired from ip addr

ethtool -i enp202s0f0np0
# driver: mlx5_core
# version: 24.10-1.1.4
# firmware-version: 16.32.2004 (DEL0000000016)
# expansion-rom-version:
# bus-info: 0000:ca:00.0
# supports-statistics: yes
# supports-test: yes
# supports-eeprom-access: no
# supports-register-dump: no
# supports-priv-flags: yes


# start mst service.
# If mst missing, do ./install_mft.sh
sudo mst start

sudo mst status
# MST devices:
# ------------
# /dev/mst/mt4119_pciconf0         - PCI configuration cycles access.
#                                    domain:bus:dev.fn=0000:31:00.0 addr.reg=88 data.reg=92 cr_bar.gw_offset=-1
#                                    Chip revision is: 00

```

Here, we can find `enp202s0f0np0` interface has bus info of `0000:ca:00.0`,
and device info `/dev/mst/mt4125_pciconf0`.


2. Set the max number of Virtual Functions
```bash
# Query the Status of the device
sudo mlxconfig -d /dev/mst/mt4125_pciconf0 q

# Enable SR-IOV , set the desired number of VFs.
sudo mlxconfig -d /dev/mst/mt4125_pciconf0 set SRIOV_EN=1 NUM_OF_VFS=4

# Reboot server.
./reboot-6.12.9.sh
```

3. Create Virtual Functions
```bash
# Get total number of VFs, should expect 8
cat /sys/class/net/enp202s0f0np0/device/sriov_totalvfs

# Get the current number of VFs on this device
cat /sys/class/net/enp202s0f0np0/device/sriov_numvfs

# Set existing VFs
# Note: sudo required
sudo bash -c "echo 4 > /sys/class/net/enp202s0f0np0/device/sriov_numvfs"

```
Check the PCI bus. 
"Virtual Function" indicates that it is a virtual function.
```bash
lspci -D | grep Mellanox

# 0000:ca:00.0 Ethernet controller: Mellanox Technologies MT2892 Family [ConnectX-6 Dx]
# 0000:ca:00.1 Ethernet controller: Mellanox Technologies MT2892 Family [ConnectX-6 Dx]
# 0000:ca:00.2 Ethernet controller: Mellanox Technologies ConnectX Family mlx5Gen Virtual Function
# 0000:ca:00.3 Ethernet controller: Mellanox Technologies ConnectX Family mlx5Gen Virtual Function
# ....
```
## Virtual Machine Setup

We define and launch a ubuntu 22 virtual machine.
The xml file assumes virtual machine image location at 
`/data/server.qcow2`. We already installed everything there.
```bash
# Define a virtual machine named network-server.
sudo virsh define network-server.xml

# You can find it with
sudo virsh list --all
```

Run it with 
```bash
sudo virsh start network-server
```

Wait for a few seconds, you can access it through console or SSH.

```bash
sudo virsh console network-server

# IP depends on your network.
ssh schai@schai@192.168.122.114
```

## Pass SR-IOV VF to VM

1. Install OFED drivers in VM.

First, we need to make sure kernel modules in the guest OS is correct.
If you compile kernel on host, then you need to copy modules into guest OS.
```bash
# On host, compressed all modules
# Right now, you should run with 6.12.9-vanilla
tar czf modules.tar.gz -C /lib/modules/$(uname -r) .

# Copy compressed file to vm
# Change name and ip if neccessary
scp modules.tar.gz schai@192.168.122.114:/tmp/

# Login to guest.
ssh schai@192.168.122.114

# In guest
sudo tar xzf /tmp/modules.tar.gz -C /lib/modules/$(uname -r)/
sudo depmod -a
```

Then, execute the commands in `setup/install_ofed.sh` with correct path to kernel source. If you have drivers installed (with our image), you can skip this step.


2. Attach VF to VM
Now we detach a virtual function from host, 
and pass it to virtual machine.
Note it requires ofed driver installed in VM. 
Our VM image already has the driver image installed for you.

Reference: https://documentation.suse.com/sles/15-SP6/html/SLES-all/cha-libvirt-config-virsh.html#sec-libvirt-config-io-attach.


```bash
sudo virsh nodedev-dumpxml pci_0000_ca_00_2 > pci_0000_ca_00_2.xml
```

Create a `cx6_vf.xml` file to descibe the virtual function.
The domain, bus, slot, and function info is from `pci_0000_ca_00_2.xml`.
```xml
<interface type='hostdev'>
 <source>
  <address type='pci' domain='0' bus='202' slot='0' function='2'/>
 </source>
</interface>
```


Detach VF from host.
If the step is correct, 
`lspci -k -s ca:00.2` should tell you that
the kernel driver in use is `vfio-pci` instead of `mlx5_core`.
```bash
sudo virsh nodedev-detach pci_0000_ca_00_2
```

Attach it to the VM and start.
Note this start will take significantly longer time as it pins all guest memory.
```bash
sudo virsh attach-device network-server cx6_vf.xml --config

sudo virsh shutdown network-server

sudo virsh start network-server
```

## Assign static IP to VF in VM.

Run `ip addr`. Here's the expected output
```md
schai@vm:~$ ip addr
# localhost interface
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
# virtio interface for host-guest communication
# 192.168.122.114 is your IP.
2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 52:54:00:ba:6d:b5 brd ff:ff:ff:ff:ff:ff
    inet 192.168.122.114/24 metric 100 brd 192.168.122.255 scope global dynamic enp1s0
       valid_lft 3432sec preferred_lft 3432sec
    inet6 fe80::5054:ff:feba:6db5/64 scope link
       valid_lft forever preferred_lft forever
# Interface passed through with VF
# We need to assign IP to it.
4: enp8s0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 52:54:00:36:54:b4 brd ff:ff:ff:ff:ff:ff

```

Creating following file `/etc/netplan/01-netcfg.yaml` 
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp8s0: # Your network interface
      dhcp4: no
      addresses:
        # - 130.127.134.200/24
        - 10.10.1.100/24  # Replace with desired static IP
      nameservers:
        addresses:
          - 8.8.8.8          # Primary DNS
          - 8.8.4.4          # Secondary DNS
```

Apply changes
```bash
sudo netplan apply
```

Now `ip addr` should give where `10.10.1.101` is our assigned IP.

```md
4: enp8s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 52:54:00:36:54:b4 brd ff:ff:ff:ff:ff:ff
    inet 10.10.1.101/24 brd 10.10.1.255 scope global enp8s0
```

Note that the IP you assign to the passed through VF in VM
should be within the subnets of host nic.
For example, host nic `enp202s0f0np0` is within subnet
`10.10.1.1/24`. We created VF from the NIC, and passed it to 
VM; it appears as `enp8s0`. Assign `enp8s0` with IP out of subnet `10.10.1.1/24` will *not* work.

Another note: When passing VFs to multiple VMs, make sure each of the VF appears with different mac address. Otherwise, network packets will be dropped.

