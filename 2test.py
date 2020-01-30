import  scapy.all  as scapy
#from scapy.layers.inet import IP, ICMP
#from scapy.layers.l2 import ARP

#from scapy.layers import  inet, l2

import platform


print (platform.system() )

if platform.system() != 'linux':
  pass




#import psutil

#addrs = psutil.net_if_addrs()
#print(addrs.keys())


# netifaces==0.10.8
# psutil==5.6.7


def arp_monitor_callback(pkt):
  if scapy.ARP in pkt and pkt[scapy.bind_layers.ARP].op in (1, 2):  # who-has or is-at
    return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")


# sniff(prn=arp_monitor_callback, filter="arp", store=0)


def packet_callback(packet):
  if packet[scapy.TCP].payload:
    pkt = str(packet[scapy.TCP].payload)
    # if packet[IP].dst == '192.168.1.10':
    print("\n{} ----HTTP----> {}:{}:\n{}".format(packet[scapy.IP].src, packet[scapy.IP].dst, packet[scapy.IP].dport,
                                                 str(bytes(packet[scapy.TCP].payload))))


# sniff( filter="tcp", prn=packet_callback, store=0, )
# scapy.sniff(iface='wlp7s0', filter="tcp", prn=packet_callback, store=0)
