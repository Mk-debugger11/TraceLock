import sys

import yaml as y
from yaml import load as ld


def read_settings(path):
    with open(path) as fh:
        return y.full_load(fh)


def read_legacy(path):
    with open(path) as fh:
        return ld(fh)


if __name__ == "__main__":
    print(read_settings(sys.argv[1]))
    print(read_legacy(sys.argv[2]))
