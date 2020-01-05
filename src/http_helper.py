from urllib import request, parse, error as urllib_error
import os
import json


def parse_headers():
  return {
    'X-Parse-Application-Id': os.environ['PARSE_APP_ID'],
    'Content-Type': 'application/json'
  }


def post_data(data, function):
  url = os.environ['PARSE_URL'] + function
  headers = parse_headers()

  if type(headers) is not dict:
    raise ValueError('Los header deben ser de tipo diccionario')
  if data is not None and type(data) is not dict:
    raise ValueError('Los datos deben ser de tipo diccionario')

  r = request.Request(url)
  r.headers = headers
  r.method = 'POST'

  response = request.urlopen(r)
  data = response.read().decode('utf-8')
  return json.loads(data)


def send_data_to_parse(data):
  result = post_data(data, os.environ['PARSE_FUNCTION'])
  return result.get('result')


def check_token():
  post_data({'token': os.environ['PARSE_SNIFFER_TOKEN']},
            os.environ['PARSE_CHECK_TOKEN_FUNCTION'])
  # todo verificar si retorna un error
  return True


def get_sniffer_config():
  result = post_data({'token': os.environ['PARSE_SNIFFER_TOKEN']},
                     os.environ['PARSE_SNIFFER_CONFIG'])
  return result.get('result')
  # todo verificar si retorna un error

# para eliminar una variable de entorno
# del  os.environ['PARSE_SNIFFER_TOKEN']
