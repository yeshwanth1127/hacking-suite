#!/bin/bash

INTERFACE="wlan0"
FAKE_IP="10.0.0.1"

# --------- Step 1: User chooses SSID ----------
read -p "Enter the fake Access Point name (SSID): " ESSID
echo "[+] Using SSID: $ESSID"

# --------- Step 2: Configure hostapd.conf ----------
echo "[+] Creating hostapd.conf..."
cat <<EOF > hostapd.conf
interface=$INTERFACE
driver=nl80211
ssid=$ESSID
hw_mode=g
channel=6
macaddr_acl=0
ignore_broadcast_ssid=0
EOF

# --------- Step 3: Assign IP automatically ----------
echo "[+] Flushing previous IP configuration on $INTERFACE..."
sudo ip addr flush dev $INTERFACE

echo "[+] Assigning $FAKE_IP to $INTERFACE..."
sudo ifconfig $INTERFACE $FAKE_IP netmask 255.255.255.0 up

# --------- Step 4: Start hostapd ----------
echo "[+] Starting Access Point with SSID: $ESSID..."
sudo hostapd hostapd.conf
