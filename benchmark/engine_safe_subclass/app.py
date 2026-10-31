import yaml


class MyLoader(yaml.SafeLoader):
    pass


def main(fh):
    return yaml.load(fh, Loader=MyLoader)
