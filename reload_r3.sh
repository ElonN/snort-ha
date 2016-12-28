#! /bin/bash

cp /mnt/proj/conf_net_r3.txt /etc/network/interfaces

cp /mnt/proj/conf_keepalive3.txt /etc/keepalived/keepalived.conf
cp /mnt/proj/keepalived.service_r3 /etc/systemd/system/keepalived.service
systemctl disable keepalived.service
systemctl enable keepalived.service
systemctl restart keepalived.service