#!/bin/bash

# get menuentry from
# awk -F\' '/menuentry / {print $2}' /boot/grub/grub.cfg
# source https://adamtheautomator.com/ubuntu-grub


GRUB_DEFAULT="/etc/default/grub"
cmd_lines=$(sudo cat $GRUB_DEFAULT | grep GRUB_CMDLINE_LINUX | grep emulabcnet)



# comment all grub_cmdline linues
IFS=$'\n'       # Set IFS to newline
for line in $cmd_lines; do
    if [[ "$line" == *#* ]]; then
        # do nothing
        :
    else
        # put # in front of the line to comment it out
        sudo sed -i "s/$line/# $line/g" $GRUB_DEFAULT
    fi
done
unset IFS       # Reset IFS


strict_line=$(grep -n GRUB_CMDLINE_LINUX $GRUB_DEFAULT | grep emulabcnet | grep "intel_iommu=on iommu.strict=1")
line_num=$(echo $strict_line | cut -d: -f1)

echo $strict_line $line_num

# uncomment the line with iommu strict
if [ "$strict_line" ]; then
    sudo sed -i "${line_num}s/^# //" $GRUB_DEFAULT
else
    $grub_line=$(sudo cat /etc/default/grub | grep GRUB_CMDLINE_LINUX | grep emulabcnet | grep -v iommu)
    modified_line=$(echo "$grub_line" | sed -E 's/"$/ intel_iommu=on iommu.strict=1"/')

    echo "$modified_line" | sudo tee -a $GRUB_DEFAULT
fi

sudo cat $GRUB_DEFAULT | grep GRUB_CMDLINE_LINUX | grep emulabcnet


echo "Please check boot kernel command line. Reboot in 20 seconds."
sleep 10

echo "Reboot in 10 seconds."
sleep 10

echo "Rebooting now."

sudo update-grub
# wef 

sudo grub-reboot "Advanced options for Ubuntu>Ubuntu, with Linux 6.0.3-vanilla"
sudo reboot

