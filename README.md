# discover switchport
A pure python script to scan the remote switch you are connected to and gives back port, name, vlan, ... using Cisco Discovery Protocol.


# requirements

depends on textual, scapy and psutil

```
sudo -i
<clone repo>
cd cdp-parser-textual
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

# running

the script has to be run as root (required vor promicous mode)

first change to root
```
sudo -i
source venv/bin/activate
```
run the script
```
python cdp-parser-textual.py
```

# tcpdump

this script does the same as the tcpdump below, but is written in python

```
sudo tcpdump -nn -v -i en0 -s 1500 'ether[20:2] == 0x2000'
```
