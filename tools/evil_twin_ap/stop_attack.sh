#!/bin/bash

INTERFACE="wlan0"

echo "[+] Stopping Evil Twin Attack..."

echo "[+] Killing processes: hostapd, dnsmasq, phishing_server.py, aireplay-ng"
sudo pkill hostapd
sudo pkill dnsmasq
sudo pkill -f phishing_server.py
sudo pkill aireplay-ng

echo "[+] Flushing IP addresses from $INTERFACE"
sudo ip addr flush dev $INTERFACE

echo "[+] Bringing $INTERFACE down and back up"
sudo ifconfig $INTERFACE down
sudo ifconfig $INTERFACE up

echo "[+] Restarting NetworkManager service"
sudo systemctl restart NetworkManager

echo "[+] Attack fully stopped, networking should be restored."
