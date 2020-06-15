import scapy.all  as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse

scapy.load_layer("http")

# from scapy.layers.inet import IP, ICMP
# from scapy.layers.l2 import ARP

# from scapy.layers import  inet, l2


from threading import Thread, Event
from time import sleep

from src.file_helper import File_helper

from src.packet_helper import  Packet_helper

import  base64

import platform




from src.env_helper import main as env_main, set_os_env
from src.http_helper import get_sniffer_config, save_details
from src.sniffer_config_helper import check_config, set_session_id
from src.scapy_helper import run_sniffing






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
  def __init__(self, interface=None, config= None):
    super().__init__()
    self.daemon = True
    self.socket = None
    self.interface = interface
    self.stop_sniffer = Event()

    self.config = config
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
      #filter="tcp &&  (src host 192.168.1.15 || dst host 192.168.1.15)"
      filter="",
      store=0
    )


  def set_config(self):
    '''
      filter config
    '''
    

  def join(self, timeout=None):
    self.stop_sniffer.set()
    super().join(timeout)

  def should_stop_sniffer(self, packet):
    return self.stop_sniffer.isSet()

  def print_packet(self, packet):
    # packet.show()

    p = self.format_package(packet)

    if p is not None:
      self.current_data.append(p)
    else:
      print ('package sport is None')
    # print (p)
    # print('[!] New Packet: {src} -> {dst}'.format(src=ip_layer.src, dst=ip_layer.dst))

  def format_package(self, packet):

    if not hasattr(packet ,'sport'):
      # print (packet)
      
      return {
        'info': Packet_helper(packet)()
      }

    ip_layer = packet.getlayer(scapy.IP)


    # packet_load = raw_layer.load  if raw_layer and raw_layer.load else None
    #packet_load = raw_layer.load if packet.haslayer(scapy.Raw) else None

    #print(packet.load)
    #print(packet.dport)
    #encodedBytes = base64.b64encode(packet.load.encode("utf-8"))
    #encodedStr = str(encodedBytes, "utf-8")

    # muestra toda la información del paquete
    # show_data = packet.show(dump = True )

    #print (type(show_data))


    #helper = Packet_helper(packet)
    # print(Packet_helper(packet)())
    #packet_json = helper.packet_to_json()

    #print (packet.payload)


    #packet.show()

    if packet.haslayer(scapy.IP):
      src = ip_layer.src
      dst = ip_layer.dst
    else :
      src = packet.src
      dst = packet.dst
    #print ('src port: {} -- dst port: {}'.format(packet.sport or  '' ,packet.dport or '' ))
    #print (packet.haslayer(HTTPResponse))

    if packet.haslayer(HTTPRequest):
      print ('------------------- request  -------------------')
      packet.show()
      '''
      url = self.get_url(packet)
      print("[+] Http Request >> " + url)
      credentials = self.get_credentials(packet)
      if credentials:
        print("[+] Possible username/passowrd " + credentials + "\n\n")
      '''

      if packet.haslayer(HTTPResponse):
        print ('------------------- response -------------------')
        packet.show()
    return {
      'src': src,
      'dst': dst,
      'sport': packet and packet.sport or  '' ,
      'dport': packet and packet.dport or '',
      'proto': packet.proto,
      'time': int( packet.time),
      'info': Packet_helper(packet)()
      # 'raw': packet_load,
      #'load_base64': encodedStr
    }

  def get_url(self, packet):
    return packet[HTTPRequest].Host + packet[HTTPRequest].Path


  def get_credentials(self,packet):
    if packet.haslayer(scapy.Raw):
      load = packet[scapy.Raw].load
      keywords = ["login", "password", "username", "user", "pass"]
      for keyword in keywords:
        if keyword in load:
          return load



class Sniffer_config():
  def __init__(self, config):
    self.config = config
    pass

  def build_filter(self):
    print(self.config)
    pass


def stop_sniffer(sniffer, file):
  sniffer.join(2.0)
  if sniffer.is_alive():
      sniffer.socket.close()
  save_details(file)
  
def save_file (sniffer):
  print('------------------------- start  write  data ----------------------------')
  file = File_helper(sniffer.current_data)
  file.start()
  file.join()
  print(file.file_name)
  # print(file.is_alive())
  # print (file.list_files())
  print('------------------------- end  write  data ----------------------------')
  return file


def run ():

  env_main()
  sniffer_config = get_sniffer_config()
  time_out = None
  if   'time' in sniffer_config:
    time_out= sniffer_config.get('time')
    

  set_session_id(sniffer_config)

  check_config(sniffer_config)
  # set_config_to_env(sniffer_config)
  run_sniffing(sniffer_config)

  sniffer = Sniffer()
  print('[*] Start sniffing…')
  sniffer.start()

  try:
    while True:
      if(time_out is not None and time_out <= 0):
        raise KeyboardInterrupt
      
      if time_out is not None:
        time_out -= 1
        print(time_out)
      sleep(1)
  except KeyboardInterrupt:
    print('[*] Stop sniffing')
    file = save_file(sniffer)
    '''
    sniffer.join(2.0)
    if sniffer.is_alive():
      sniffer.socket.close()
    save_details(file)
    '''
    stop_sniffer(sniffer, file)
  # print(scapy.IP)


run()

#raise KeyboardInterrupt
