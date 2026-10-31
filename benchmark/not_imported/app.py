import json


def load_config(path):
    with open(path) as fh:
        return json.load(fh)


if __name__ == "__main__":
    print(load_config("config.json"))
