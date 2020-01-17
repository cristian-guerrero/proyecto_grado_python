
from datetime import datetime
import os
from os.path import isfile, join
from os import listdir
import json


def file_name():
  ''' Crear un nombre de archivo añadiendole el timestamp del sistema '''
  return 'sniff_' + timestamp_str() + '.json'


def timestamp_str():
  ''' Devuelte un timestamp en formato de string  '''
  now = datetime.now()
  return str(int(datetime.timestamp(now)))


def new_file():
  ''' Crear un nuevo archivo en la carpeta logs, si no existe se crea el directorio '''
  if not os.path.exists('logs'):
    os.makedirs('logs')
  f = open('logs/' + file_name(), "w")
  # f.write('line --')
  # f.close()

  return f


def delete_files():
  ''' Elimina los archivos del directorio logs '''
  for f in list_files():
    os.remove(join('logs', f))


def delete_one_file(file):
  ''' Elimina un solo archivo del directorio logs '''
  os.remove(join('logs', file))


def list_files():
  '''Devuelve la lista de archivos existentes en el directorio logs '''
  path = 'logs'
  return [f for f in listdir(path) if isfile(join(path, f)) and f.find('sniff_1') > -1]


def write_json_to_file(data, file):
  ''' Scribe el contenido de un json en un archivo '''
  # en producción se debe quitar la identación para reducir el tamaño del archivo
  json.dump(data, file, indent=2)
  # json.dump(data, file)


def read_json_from_file(file):
  ''' Lee un archivo y devuelve su contenido en formato json '''
  return json.load(file)
