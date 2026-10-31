import sys
import yaml


def load(path, loader_name):
    fn = getattr(yaml, loader_name)
    with open(path) as fh:
        return fn(fh)


if __name__ == "__main__":
    print(load(sys.argv[1], sys.argv[2]))
