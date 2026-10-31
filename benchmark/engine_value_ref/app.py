import yaml


def parse(fh, loader_fn):
    return loader_fn(fh, Loader=yaml.FullLoader)
