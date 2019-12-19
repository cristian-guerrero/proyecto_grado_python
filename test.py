

from urllib import request, parse, error as urllib_error
import json
# logging
import logging
logger = logging.Logger('catch_all')


app_id = 'proyectoGradoSniffer'
function = '_recibe_sniffer_data'
url = 'http://localhost:5337/sniffer-backend/functions/_recibe_sniffer_data'
rest_api_key = 'FFLDkTJHrEjqgRoa23DT2suHqYMmvyhRJThKPcfLZpf3rB5tJddaVVo45d5rhHx3ApjBFezvPMTnB4xhQcXMsEy4L6craPBJxgZUz8Mr7uAFiVsezpcUdeJpgH3'
headers = {
    "X-Parse-Application-Id": app_id,
    # "X-Parse-REST-API-Key": rest_api_key,
    "Content-Type": "application/json"
}


def send_data_to_parse(data):
    post_data(url, parse_headers(), data)


def post_data(url, headers, data):
    if type(headers) is not dict:
        raise ValueError('Los header deben ser de tipo diccionario')
    if data is not None and type(data) is not dict:
        raise ValueError('Los datos deben ser de tipo diccionario')

    r = request.Request(url)
    r.headers = headers
    r.method = 'POST'

    response = request.urlopen(r)
    data = response.read().decode('utf-8')
    print(data)
    return data


def parse_headers():
    return {
        "X-Parse-Application-Id": app_id,
        "X-Parse-REST-API-Key": rest_api_key,
        "Content-Type": "application/json"
    }

def parse_json(data):
    pass

try:
    data = send_data_to_parse(())
    print(data)
except urllib_error.HTTPError as e:

    logger.error(e, exc_info=True)
except Exception as e :
    logger.error(e, exc_info=True)
