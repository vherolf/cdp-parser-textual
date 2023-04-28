#! /usr/bin/env python

# parse for a cdp package to find on which remote Cisco switch and port its connected 
from scapy.all import *

load_contrib("cdp")
 
def cdp_monitor_callback(pkt):
  ip = "0.0.0.0"
  if (CDPMsgDeviceID in pkt):
    device=pkt["CDPMsgDeviceID"].val.decode()
    hostname=device.split(".")[0]
    if (CDPMsgPortID in pkt):
      port = pkt["CDPMsgPortID"].iface.decode()
    if (CDPMsgDeviceID in pkt):
      switchname = pkt["CDPMsgDeviceID"].val.decode()
    if (CDPMsgNativeVLAN in pkt):
      vlan = pkt["CDPMsgNativeVLAN"].vlan
    if (CDPAddrRecordIPv4 in pkt):
      ip=pkt["CDPAddrRecordIPv4"].addr
    return f"Device: {switchname} Port: {port} VLAN: {vlan} IP: {ip}"
 
interface="eno1"
capturefilter="ether dst 01:00:0c:cc:cc:cc"
 
# run it for max. 99 Packets
p=sniff(prn=cdp_monitor_callback, iface=interface, count=1, filter=capturefilter, store=0)
