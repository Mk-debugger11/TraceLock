import yaml
from yaml import SafeLoader


def main(fh):
    return yaml.load(fh, Loader=SafeLoader)
