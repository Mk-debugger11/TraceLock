import sys
from types import SimpleNamespace

import yaml


def make_config(strict):
    return SimpleNamespace(loader=yaml.SafeLoader if strict else yaml.FullLoader)


def load_document(path, cfg):
    with open(path) as fh:
        return yaml.load(fh, Loader=cfg.loader)


if __name__ == "__main__":
    print(load_document(sys.argv[1], make_config("--strict" in sys.argv)))
