import yaml


class MyLoader(yaml.FullLoader):
    pass


def main(fh):
    return yaml.load(fh, Loader=MyLoader)
