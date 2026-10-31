try:
    import yaml
except ImportError:
    yaml = None


def main(fh):
    if yaml:
        return yaml.load(fh)
