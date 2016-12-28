#! /bin/bash

cp /mnt/proj/conf_net_snort2.txt /etc/network/interfaces

cp /mnt/proj/pyhttp_get.service_snort2 /etc/systemd/system/pyhttp_get.service
systemctl disable pyhttp_get.service
systemctl enable pyhttp_get.service
systemctl restart pyhttp_get.service

cp /mnt/proj/snort.service /etc/systemd/system
systemctl disable snort.service
systemctl enable snort.service
systemctl restart snort.service