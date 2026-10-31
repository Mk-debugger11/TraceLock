import yaml


class Base:
    def parse(self, fh):
        return yaml.load(fh)


class Child(Base):
    def run(self, fh):
        return self.parse(fh)


def main(fh):
    return Child().run(fh)
