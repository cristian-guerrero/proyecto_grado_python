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
## ejemplo de como se debe ver un filtro
#sniffed = scapy.sniff(iface='enp0s3', filter="tcp &&  (src host 192.168.1.15 || dst host 192.168.1.15)", prn=packet_callback, store=0)



# ejemplo de como salir del sniff con un evento de hilo
import time, threading
e = threading.Event()
def _sniff(e):
  a = scapy.sniff(iface=None,filter="tcp port 443", stop_filter=lambda p: e.is_set())
  print("Stopped after %i packets" % len(a))

print("Start capturing thread")
t = threading.Thread(target=_sniff, args=(e,))
t.start()

time.sleep(3)
print("Try to shutdown capturing...")
e.set()

# This will run until you send a HTTP request somewhere
# There is no way to exit clean if no package is received
while True:
  t.join(2)
  if t.is_alive():
    print("Thread is still running...")
  else:
    break

print("Shutdown complete!")


## ejemplo sencillo

interface = None

def print_packet(packet):
  ip_layer = packet.getlayer(scapy.IP)
  print("[!] New Packet: {src} -> {dst}".format(src=ip_layer.src, dst=ip_layer.dst))

print("[*] Start sniffing...")
scapy.sniff(iface=interface, filter="ip", prn=print_packet)
print("[*] Stop sniffing")
