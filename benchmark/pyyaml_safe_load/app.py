import yaml


def load_config(path):
    with open(path) as fh:
        return yaml.safe_load(fh)


def dump(obj):
    return yaml.safe_dump(obj)


if __name__ == "__main__":
    print(load_config("config.yaml"))
