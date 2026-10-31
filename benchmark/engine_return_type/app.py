import yaml


class Parser:
    def parse(self, fh):
        return yaml.load(fh)


def make_parser():
    return Parser()


def main(fh):
    p = make_parser()
    return p.parse(fh)
