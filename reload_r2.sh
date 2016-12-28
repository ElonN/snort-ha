#! /bin/bash

cp /mnt/proj/conf_net_r2.txt /etc/network/interfaces

cp /mnt/proj/conf_keepalive2.txt /etc/keepalived/keepalived.conf
cp /mnt/proj/keepalived.service_r2 /etc/systemd/system/keepalived.service
systemctl disable keepalived.service
systemctl enable keepalived.service
systemctl restart keepalived.service

cp /mnt/proj/pyhttp.service /etc/systemd/system
systemctl disable pyhttp.service
systemctl enable pyhttp.service
systemctl restart pyhttp.service