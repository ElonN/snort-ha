#! /bin/bash

cp /mnt/proj/conf_net_r3.txt /etc/network/interfaces

/mnt/proj/enable_ipforward.sh

apt-get install keepalived

mkdir /etc/keepalived
cp /mnt/proj/conf_keepalive3.txt /etc/keepalived/keepalived.conf
cp /mnt/proj/bypass_ipvs.sh /etc/keepalived

# install keepalived as service (should be run by root at init)
cp /mnt/proj/keepalived.service_r3 /etc/systemd/system/keepalived.service
systemctl enable keepalived.service
