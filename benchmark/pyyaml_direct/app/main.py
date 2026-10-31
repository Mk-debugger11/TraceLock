import sys
import yaml


def load_config(path):
    with open(path) as fh:
        return yaml.load(fh)


def main():
    cfg = load_config(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")
    print(cfg)


if __name__ == "__main__":
    main()
