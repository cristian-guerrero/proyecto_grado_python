
from src.env_helper import main as env_main
from src.http_helper import send_data_to_parse


def run():
    env_main()


if __name__ == "__main__":
    run()
    send_data_to_parse({})
