import yaml


def load_config(path):
    with open(path) as fh:
        return yaml.load(fh, Loader=yaml.SafeLoader)


if __name__ == "__main__":
    print(load_config("config.yaml"))
