import argparse
from datetime import datetime
import json
import os
from os import listdir
from os.path import isfile, join
from sys import getsizeof
#from scapy.all import *
import scapy.all  as scapy

from src.file_helper import new_file, write_json_to_file, list_files, read_json_from_file, var_size

from threading import Thread, Event
from time import sleep



# from scapy.all import ARP, ByteField, Ether, Dot1Q, STP, Dot3, IP, IPv6, ICMP, TCP, UDP, Packet, sniff



def run_sniffing(config):

  print ('run_sniffing' , config)
  f = new_file()

  data = {}

  print(var_size(data))

  write_json_to_file(data, f)

  f.close()

  files = list_files()
  for f2 in files:
    # print(f2)
    f3 = open('logs/' + f2)
    json_data = read_json_from_file(f3)
    # print(json_data)


def send_data(data):
  print('')


def stopfilter(x):
  '''
  Funcion para detener el sniffer cuando la condicion se cumpla
  sniff(iface="wlan0", filter='tcp', stop_filter=stopfilter)

  :param x:
  :return:
  '''
  return False

def build_filter():
  pass

# ipsDestino == dst
# ipsOrigin == src
# and ==  and (&&)
# or == or (||)
