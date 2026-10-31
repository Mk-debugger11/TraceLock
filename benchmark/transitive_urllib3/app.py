import sys

import requests


def check_status(url):
    resp = requests.get(url, timeout=5)
    return resp.status_code


if __name__ == "__main__":
    print(check_status(sys.argv[1]))
