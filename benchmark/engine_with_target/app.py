import yaml


class Reader:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def read(self, fh):
        return yaml.full_load(fh)


def main(fh):
    with Reader() as r:
        return r.read(fh)
