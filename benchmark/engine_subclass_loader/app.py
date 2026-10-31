import yaml


class MyLoader(yaml.FullLoader):
    pass


def main():
    return MyLoader
