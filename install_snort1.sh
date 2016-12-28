#! /bin/bash
sudo apt-get install -y binutils gcc

sudo apt-get install -y build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev
sudo apt-get install -y libluajit-5.1-dev pkg-config

# install libhiredis
sudo apt-get install -y libhiredis-dev

# turn off device features
sudo ethtool -K ens38 gro off
sudo ethtool -K ens38 lro off
sudo ethtool -K ens39 gro off
sudo ethtool -K ens39 lro off

# install DAQ libraries
mkdir ~/snort_src
cd ~/snort_src
cp /mnt/proj/daq-2.0.6.tar.gz .
tar -xvzf daq-2.0.6.tar.gz  
cd daq-2.0.6
./configure
make
sudo make install

# make a symlink
sudo ln -s /usr/local/bin/snort /usr/sbin/snort

# updates all dynamic libraries
sudo ldconfig

# VERY important, configures LUA library, if snort ever fails to run with some LUA error - run this
export LUA_PATH=/usr/local/include/snort/lua/\?.lua\;\;
export SNORT_LUA_PATH=/usr/local/etc/snort
sudo sh -c "echo 'LUA_PATH=/usr/local/include/snort/lua/\?.lua\;\;' >> /etc/environment"
sudo sh -c "echo 'SNORT_LUA_PATH=/usr/local/etc/snort' >> /etc/environment"

cd /mnt/proj/snort-3.0.0-a2
./configure
make -j 8

cp /mnt/proj/conf_net_snort1.txt /etc/network/interfaces
systemctl enable pyhttp_get.service

cp /mnt/proj/snort.service /etc/systemd/system
systemctl enable snort.service