import yaml as y


def _read(fh):
    return y.full_load(fh)


def load_settings(path):
    with open(path) as fh:
        return _read(fh)
