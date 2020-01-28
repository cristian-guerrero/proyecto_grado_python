from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP

import platform


print (platform.system() )


import psutil

addrs = psutil.net_if_addrs()
print(addrs.keys())


# netifaces==0.10.8
# psutil==5.6.7



def arp_monitor_callback(pkt):
  if ARP in pkt and pkt[ARP].op in (1, 2):  # who-has or is-at
    return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")


# sniff(prn=arp_monitor_callback, filter="arp", store=0)


def packet_callback(packet):
  if packet[TCP].payload:
    pkt = str(packet[TCP].payload)
    # if packet[IP].dst == '192.168.1.10':
    print("\n{} ----HTTP----> {}:{}:\n{}".format(packet[IP].src, packet[IP].dst, packet[IP].dport,
                                                 str(bytes(packet[TCP].payload))))


sniff( filter="tcp", prn=packet_callback, store=0, )
#sniff(iface='en0', filter="tcp", prn=packet_callback, store=0)
