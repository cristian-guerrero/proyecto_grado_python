# todo verificar que la configuracion del sniffer sea adecuada
# mostrar error si alguna configuración esta mal
# verifir si en la configuración vienen todos los valores requeridos y si no llegan
# llenarlos con un valor por defecto

from src.env_helper import  set_os_env

def check_config(config):
  pass


def set_session_id(config ) :
  set_os_env({'PARSE_SESSION_ID': config['session']})

