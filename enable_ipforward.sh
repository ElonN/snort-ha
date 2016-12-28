#! /bin/bash

# This enables IP forwarding so that the machine can function as a router
# The command itself replaces the string "#net.ipv4.ip_forward=1" with "net.ipv4.ip_forward=1" (uncomments this line)
# in the file /etc/sysctl.conf
# As a result - IP forwarding is enabled every boot
sudo sed -i "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g" /etc/sysctl.conf
