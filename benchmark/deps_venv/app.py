import sys

import yaml


def load_config(path):
    with open(path) as fh:
        return yaml.load(fh)


if __name__ == "__main__":
    print(load_config(sys.argv[1]))
