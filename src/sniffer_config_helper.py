# todo verificar que la configuracion del sniffer sea adecuada
# mostrar error si alguna configuración esta mal
# verifir si en la configuración vienen todos los valores requeridos y si no llegan
# llenarlos con un valor por defecto

from src.env_helper import  set_os_env

def check_config(config):

  if not config['sessionId']:
    raise Exception('El backend no devolvio el sessionId')


def set_session_id(config ) :
  print(config['sessionId'])
  check_config(config)
  set_os_env({'PARSE_SESSION_ID': config['sessionId']})

