import argparse
from datetime import datetime
import json
import os
from os import listdir
from os.path import isfile, join
from sys import getsizeof
from scapy.all import *


# from scapy.all import ARP, ByteField, Ether, Dot1Q, STP, Dot3, IP, IPv6, ICMP, TCP, UDP, Packet, sniff


def file_name():
  return 'sniff_' + timestamp_str() + '.json'


def timestamp_str():
  now = datetime.now()
  return str(int(datetime.timestamp(now)))


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


def new_file():
  if not os.path.exists('logs'):
    os.makedirs('logs')
  f = open('logs/' + file_name(), "w")
  # f.write('line --')
  # f.close()

  return f


def delete_files():
  for f in list_files():
    os.remove(join('logs', f))


def delete_one_file(file):
  os.remove(join('logs', file))


def list_files():
  path = 'logs'
  return [f for f in listdir(path) if isfile(join(path, f)) and f.find('sniff_1') > -1]


def write_json_to_file(data, file):
  # en producción se debe quitar la identación para reducir el tamaño del archivo
  json.dump(data, file, indent=2)
  # json.dump(data, file)


def read_json_from_file(file):
  return json.load(file)


def var_size(data):
  size_in_bytes = getsizeof(data)
  print(size_in_bytes)
  # tamaño en megabites
  # return round(size_in_bytes * 2**-20, 6)
  return round(size_in_bytes * 1024 ** -2, 6)
