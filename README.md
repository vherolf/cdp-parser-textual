# Discover Cisco switchport

A pure python script to scan the remote Cisco switch you are connected to and gives back port, name, vlan, ... using Cisco Discovery Protocol.


# Install

Depends on textual, scapy and psutil.

```
sudo -s
<clone repo>
cd cdp-parser-textual
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

# Running

The script has to be run as root (required for promicous mode)

first change to root
```
sudo -s
source venv/bin/activate
```
run the script
```
python cdp-parser-tui.py
```

# tcpdump

This script does the same as the tcpdump below, but its written in python.

```
sudo tcpdump -nn -v -i en0 -s 1500 'ether[20:2] == 0x2000'
```
