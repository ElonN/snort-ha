#! /bin/bash

# run this from within project folder
# flags:
#  -c       configuration file
#  --daq    data aquisition library to use
#  -Q       run in IPS inline mode
#  -i       run as bridge between two interfaces "interface1:interface2"
src/snort -c lua/snort.lua --daq afpacket -Q -i "ens38:ens39"