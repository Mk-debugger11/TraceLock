import json
import sys

from tqdm import tqdm


def count_records(paths):
    total = 0
    for path in tqdm(paths, desc="files"):
        with open(path) as fh:
            total += len(json.load(fh))
    return total


if __name__ == "__main__":
    print(count_records(sys.argv[1:]))
