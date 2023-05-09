from textual.app import App, ComposeResult
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Input, Button, Label, Header, Footer, Static, TextLog, ListView, ListItem
from textual import events
from textual.containers import VerticalScroll

import psutil

from scapy.all import *
load_contrib("cdp")

class Result(Widget):
    interface = reactive("", layout=True)  
    switchname = reactive("", layout=True)  
    port = reactive("", layout=True)  
    vlan = reactive("", layout=True)  
    ip = reactive("", layout=True)  
    
    def render(self) -> str:
        return f"Interface: {self.interface}\nDevice: {self.switchname}\nPort: {self.port}\nVLAN: {self.vlan}\nIP: {self.ip}"
        
class CDPScanApp(App):
    TITLE = "CDP Scan App"
    CSS= """Screen {
            align: center middle;
            }

            ListView {
                width: 30;
                height: auto;
                margin: 2 2;
            }

            Label {
                padding: 1 2;
            } 
        """

    def compose(self) -> ComposeResult:
        for item in psutil.net_if_addrs().keys():
            yield Button(label=item, id=item)
        yield Button("Scan", id="scan", variant="primary", disabled=False)
        yield Result()
        #yield VerticalScroll(Static(id="results"), id="results-container")
        
    def analyze(self, pkt) -> None:
        """ scan for cdp package"""
        ip = "0.0.0.0"
        if (CDPMsgDeviceID in pkt):
            device=pkt["CDPMsgDeviceID"].val.decode()
            hostname=device.split(".")[0]
            if (CDPMsgPortID in pkt):
                port = pkt["CDPMsgPortID"].iface.decode().replace("GigabitEthernet0/","")
            if (CDPMsgDeviceID in pkt):
                switchname = pkt["CDPMsgDeviceID"].val.decode()
            if (CDPMsgNativeVLAN in pkt):
                vlan = pkt["CDPMsgNativeVLAN"].vlan
            if (CDPAddrRecordIPv4 in pkt):
                ip=pkt["CDPAddrRecordIPv4"].addr
            self.query_one(Result).switchname = switchname
            self.query_one(Result).port = port
            self.query_one(Result).vlan = vlan
            self.query_one(Result).ip = ip
        
    def scan(self):
        interface = self.query_one(Result).interface
        capturefilter="ether dst 01:00:0c:cc:cc:cc"
        # run it for max. 1 Packets
        sniff(prn=self.analyze, iface=interface, count=1, filter=capturefilter, store=0)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "scan":
            self.scan()
        else:
            print(event.button.id)
            self.query_one(Result).interface = event.button.id

if __name__ == "__main__":
    app = CDPScanApp()
    app.run()
