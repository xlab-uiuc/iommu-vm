#!/usr/bin/env bash

VM="network-server"
target="schai@10.10.1.1"


sudo virsh shutdown $VM

dom_path=$(sudo virsh domblklist network-server | grep vda | awk '{print $2}')

xml_path=$VM.xml
sudo virsh dumpxml $VM > $xml_path
echo $xml_path
# cat $xml_path

sudo chmod +666 $dom_path
sudo chmod +666 $xml_path
rsync -avh --progress $dom_path $target:$dom_path
rsync -avh --progress $xml_file $target:$xml_file