import sys

from yaml import *


def read_config(path):
    with open(path) as fh:
        return load(fh)


if __name__ == "__main__":
    print(read_config(sys.argv[1]))
