from urllib import request, parse, error as urllib_error
import os
import json
from urllib.error import HTTPError


def parse_headers():
  ''' Retorna los headers necesarios para realizar la peticion a perse server '''
  return {
    'X-Parse-Application-Id': os.environ['PARSE_APP_ID'],
    'Content-Type': 'application/json',
    'sniffer-token': os.environ['PARSE_SNIFFER_TOKEN']
  }


def post_data(data, function):
  '''
  Realiza una peticion post con los datos recibidos como parametro
  a la funcion parse recibida como parametro
  '''
  try:
    url = os.environ['PARSE_URL'] + function
    headers = parse_headers()

    if type(headers) is not dict:
      raise ValueError('Los header deben ser de tipo diccionario')
    if data is not None and type(data) is not dict:
      raise ValueError('Los datos deben ser de tipo diccionario')

    data = json.dumps(data)
    data = data.encode('ascii')

    r = request.Request(url=url, method='POST', headers=headers, data=data)

    response = request.urlopen(r)
    data = response.read().decode('utf-8')
    return json.loads(data)

  except HTTPError as err:
    print('http error->', err.read().decode())
    # raise Exception(err.read().decode() )
  except Exception as error:
    print('post_data general error-> ', error)


def send_data_to_parse(data):
  ''' Envia datos al servidor parse server y devuelve el resultado  '''
  result = post_data(data, os.environ['PARSE_FUNCTION'])
  return result.get('result')


def check_token():
  '''
  TODO almacenar el id de session devuelto por parse server en una varialble de sistema
    que pueda ser utilizada posteriormente en el envio de datos capturados
  Verifica si el token es valido,
  si el token es valido parse devuelve el id de una session almacendad en la clase Data
  del servidor parse, que sera necesario despues para enviar los datos capturados
  :return:
  '''
  post_data({'token': os.environ['PARSE_SNIFFER_TOKEN']},
            os.environ['PARSE_CHECK_TOKEN_FUNCTION'])
  # todo verificar si retorna un error
  return True


def get_sniffer_config():
  ''' Recupera la configuración del sniffer almacenda en el backend de parse '''
  result = post_data({'token': os.environ['PARSE_SNIFFER_TOKEN']},
                     os.environ['PARSE_SNIFFER_CONFIG'])

  print (result.get('result'))
  return result.get('result')
  # todo verificar si retorna un error

# para eliminar una variable de entorno
# del  os.environ['PARSE_SNIFFER_TOKEN']
