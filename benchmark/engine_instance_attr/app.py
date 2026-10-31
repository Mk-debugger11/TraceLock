import yaml


class YamlParser:
    def load(self, fh):
        return yaml.load(fh)


class Service:
    def __init__(self):
        self.parser = YamlParser()

    def run(self, fh):
        return self.parser.load(fh)


def main(fh):
    return Service().run(fh)
