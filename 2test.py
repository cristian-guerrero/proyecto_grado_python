import scapy.all  as scapy
# from scapy.layers.inet import IP, ICMP
# from scapy.layers.l2 import ARP

# from scapy.layers import  inet, l2


from threading import Thread, Event
from time import sleep

from src.file_helper import File_helper, new_file, write_json_to_file, list_files, read_json_from_file, var_size

import platform

print(platform.system())

if platform.system() != 'linux':
  pass


# import psutil

# addrs = psutil.net_if_addrs()
# print(addrs.keys())


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
# sniffed = scapy.sniff(iface='enp0s3', filter="tcp &&  (src host 192.168.1.15 || dst host 192.168.1.15)", prn=packet_callback, store=0)


# ejemplo de como salir del sniff con un evento de hilo
'''
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
'''

## ejemplo sencillo
'''
interface = None

def print_packet(packet):
  ip_layer = packet.getlayer(scapy.IP)
  print("[!] New Packet: {src} -> {dst}".format(src=ip_layer.src, dst=ip_layer.dst))

print("[*] Start sniffing...")
scapy.sniff(iface=interface, filter="ip", prn=print_packet)
print("[*] Stop sniffing")
'''

# ejemplo sniffer en clase e hilo
'''
class Sniffer(Thread):
  def __init__(self, interface=None):
    super().__init__()

    self.interface = interface
    self.stop_sniffer = Event()

  def run(self):
    scapy.sniff(iface=self.interface, filter='ip', prn=self.print_packet, stop_filter=self.should_stop_sniffer)

  def join(self, timeout=None):
    self.stop_sniffer.set()

    super().join(timeout)

  def should_stop_sniffer(self, packet):
    return self.stop_sniffer.isSet()

  def print_packet(self, packet):
    ip_layer = packet.getlayer(scapy.IP)

    print('[!] New Packet: {src} -> {dst}'.format(src=ip_layer.src, dst=ip_layer.dst))



sniffer = Sniffer()
print('[*]Startsniffing…')
sniffer.start()
try:
  while True:
    sleep(100)
except KeyboardInterrupt:
  print('[*] Stops niffing')
  sniffer.join()
'''


# ejemplo sniffer en clase e hilo con salida

class Sniffer(Thread):
  def __init__(self, interface=None):
    super().__init__()
    self.daemon = True
    self.socket = None
    self.interface = interface
    self.stop_sniffer = Event()
    #
    self.current_data = []

  def run(self):
    self.socket = scapy.conf.L2listen(
      type=scapy.ETH_P_ALL,
      iface=self.interface,
      filter='ip'
    )
    scapy.sniff(
      opened_socket=self.socket,
      prn=self.print_packet,
      stop_filter=self.should_stop_sniffer,
      filter="tcp &&  (src host 192.168.1.15 || dst host 192.168.1.15)"
    )

  def join(self, timeout=None):
    self.stop_sniffer.set()
    super().join(timeout)

  def should_stop_sniffer(self, packet):
    return self.stop_sniffer.isSet()

  def print_packet(self, packet):
    # packet.show()

    p = self.format_package(packet)

    self.current_data.append(p)
    # print (p)
    # print('[!] New Packet: {src} -> {dst}'.format(src=ip_layer.src, dst=ip_layer.dst))

  def format_package(self, packet):
    '''
    ip_layer = packet.getlayer(scapy.IP)
    raw_layer = packet.getlayer(scapy.Raw)
    tcp_layer = packet.getlayer(scapy.TCP)
    udp_layer = packet.getlayer(scapy.UDP)

    if packet.haslayer(scapy.TCP):
      sport = tcp_layer.sport
      dport = tcp_layer.dport
    elif  packet.haslayer(scapy.UDP) :
      dport = udp_layer.dport
      sport = udp_layer.sport
    else:
      sport = ''
      dport= ''
    '''

    # packet_load = raw_layer.load  if raw_layer and raw_layer.load else None
    #packet_load = raw_layer.load if packet.haslayer(scapy.Raw) else None

    print(packet.load)
    print(packet.dport)
    return {
      'src': packet.src,
      'dst': packet.dst,
      'sport': packet.sport,
      'dport': packet.dport,
      # 'raw': packet_load
    }


class Sniffer_config():
  def __init__(self, config):
    self.config = config
    pass

  def build_filter(self):
    print(self.config)
    pass


sniffer = Sniffer()
print('[*] Start sniffing…')
sniffer.start()

try:
  while True:
    sleep(100)
except KeyboardInterrupt:
  print('[*] Stop sniffing')
  # print(sniffer.current_data)
  print('------------------------- start  write  data ----------------------------')
  file = File_helper(sniffer.current_data)
  file.start()
  print(file.file_name)
  # print(file.is_alive())
  # print (file.list_files())
  print('------------------------- end  write  data ----------------------------')

  sniffer.join(2.0)
  if sniffer.is_alive():
    sniffer.socket.close()

print(scapy.IP)
