
from datetime import datetime
import os
from os.path import isfile, join
from os import listdir
import json



def file_name():
  return 'sniff_' + timestamp_str() + '.json'


def timestamp_str():
  now = datetime.now()
  return str(int(datetime.timestamp(now)))



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
