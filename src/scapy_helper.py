import argparse
from datetime import datetime
import json
import os
from os import listdir
from os.path import isfile, join
from sys import getsizeof
from scapy.all import *

from src.file_helper import new_file, write_json_to_file, list_files, read_json_from_file




# from scapy.all import ARP, ByteField, Ether, Dot1Q, STP, Dot3, IP, IPv6, ICMP, TCP, UDP, Packet, sniff



def run_sniffing(config):
  f = new_file()

  data = {}
  for i in range(10000):
    data_t = 'data {}'.format(i)
    data[data_t] = []
    data[data_t].append({
      'name': 'Tim',
      'website': 'apple.com',
      'from': 'Alabama'
    })

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




def var_size(data):
  size_in_bytes = getsizeof(data)
  print(size_in_bytes)
  # tamaño en megabites
  # return round(size_in_bytes * 2**-20, 6)
  return round(size_in_bytes * 1024 ** -2, 6)
