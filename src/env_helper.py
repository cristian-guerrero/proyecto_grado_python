import os
import sys

default_keys = [
  'PARSE_APP_ID',
  'PARSE_FUNCTION',
  'PARSE_URL',
  'PARSE_SNIFFER_TOKEN',
  'PARSE_SNIFFER_CONFIG',
  'PARSE_CHECK_TOKEN_FUNCTION'
]


def set_os_env(values):
  if type(values) is not dict:
    raise ValueError(
      'Se require un diccionario para establecer las variables de entorno en el sistema operativo')
  for key, value in values.items():
    # print(' {}: {}'.format(key, value))
    os.environ[key] = value

    # print('os -> {} : {}'.format(key, os.environ[key]))


def load_env_file():
  path = '.env'
  splitter = '='
  if not os.path.isfile(path):
    raise ValueError(
      'El archivo .env no existe, es requerido para cargar la configuración')
    # sys.exit()
  f = open('.env', 'r')
  line = f.readline()
  result = {}
  while line:
    string = line.strip()
    if (string.find(splitter) > -1):
      splited = string.split(splitter)
      key = splited[0].strip()
      value = splited[1].strip()
      result[key] = value
    line = f.readline()
  return result


def check_keys_in_dic(keys, dictionary):
  result = []
  for k in keys:
    if k not in dictionary:
      result.append(k)
  return result


def main():
  val = load_env_file()
  arr = check_keys_in_dic(default_keys, val)
  if len(arr) > 0:
    txt = 'Faltan los valores para: {} en el archivo .env'.format(
      ''.join([str(elem) for elem in arr]))
    raise ValueError(txt)

  set_os_env(val)


if __name__ == "__main__":
  pass
  # main()

# print(load_env_file())
