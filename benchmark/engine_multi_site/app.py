import yaml


def helper_nobody_calls(fh):
    return yaml.load(fh)


def used(fh):
    return yaml.full_load(fh)


def main():
    with open("c.yaml") as fh:
        used(fh)


if __name__ == "__main__":
    main()
