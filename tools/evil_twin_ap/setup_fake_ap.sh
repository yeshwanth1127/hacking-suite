#!/bin/bash

TARGET_FILE="../../tools/target_selector/selected_target.json"
SSID=$(jq -r '.ESSID' $TARGET_FILE)
CHANNEL=$(jq -r '.Channel' $TARGET_FILE)
INTERFACE="wlan0"

echo "[+] Setting up hostapd with SSID: $SSID on Channel: $CHANNEL"

cat <<EOF > hostapd.conf
interface=$INTERFACE
driver=nl80211
ssid=$SSID
hw_mode=g
channel=$CHANNEL
macaddr_acl=0
ignore_broadcast_ssid=0
EOF

echo "[+] Starting Access Point..."
hostapd hostapd.conf
