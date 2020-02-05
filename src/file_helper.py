from datetime import datetime
import os
from os.path import isfile, join
from os import listdir
import json
from sys import getsizeof

from threading import Thread, Event
from time import sleep


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


def var_size(data):
  '''
  Devuelve al tamaño que ocupa una variable en memoria en Mbs
  :param data:
  :return:
  '''
  size_in_bytes = getsizeof(data)
  # print(size_in_bytes)
  # tamaño en megabites
  # return round(size_in_bytes * 2**-20, 6)
  return round(size_in_bytes * 1024 ** -2, 6)


class File_helper(Thread):

  def __init__(self, data):
    self.data = data
    self.file_name =  None
    self.generate_file_name()

    super().__init__()

  def run(self):
    self.write()
    pass

  def join(self, timeout=None):
    pass

  def generate_file_name(self):
    ''' Crear un nombre de archivo añadiendole el timestamp del sistema '''
    self.file_name =  'logs/' + 'sniff_' + self.timestamp_str() + '.json'

  def timestamp_str(self):
    ''' Devuelte un timestamp en formato de string  '''
    now = datetime.now()
    return str(int(datetime.timestamp(now)))

  def new_file(self):
    ''' Crear un nuevo archivo en la carpeta logs, si no existe se crea el directorio '''
    if not os.path.exists('logs'):
      os.makedirs('logs')

    f = open(self.file_name, "w")
    # f.write('line --')
    # f.close()

    return f

  def write(self):
    ''' Scribe el contenido de un json en un archivo '''
    # en producción se debe quitar la identación para reducir el tamaño del archivo

    file = self.new_file()
    json.dump(self.data, file, indent=2)
    file.close()
    # join permite espeara hasta que el hilo termine su tarea
    # permitiendo tener acceso al archivo ya creado
    # se deve ejecutar cuando se necesite tener acceso al archivo para continuar otra tarea
    #self.join()
    # json.dump(data, file)

  def read_json_from_file(file):
    ''' Lee un archivo y devuelve su contenido en formato json '''
    return json.load(file)

  def delete_files(self):
    ''' Elimina los archivos del directorio logs '''
    for f in self.list_files():
      os.remove(join('logs', f))


  def delete_one_file(self, file):
    ''' Elimina un solo archivo del directorio logs '''
    os.remove(join('logs', file))


  def list_files(self):
    '''Devuelve la lista de archivos existentes en el directorio logs '''
    path = 'logs'
    return [f for f in listdir(path) if isfile(join(path, f)) and f.find('sniff_1') > -1]
