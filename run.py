import sys

from src.env_helper import main as env_main
from src.http_helper import get_sniffer_config
from src.sniffer_config_helper import check_config
from src.scapy_helper import run_sniffing


def run():
  '''
  Función que permite arrancar la aplicación de sniffing
   '''

  env_main()
  sniffer_config = get_sniffer_config()
  check_config(sniffer_config)
  # set_config_to_env(sniffer_config)
  run_sniffing(sniffer_config)


if __name__ == "__main__":
  run()
