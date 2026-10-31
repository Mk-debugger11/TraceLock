import sys

import requests


def fetch_profile(url, token):
    s = requests.Session()
    s.headers.update({"X-Api-Token": token})
    resp = s.get(url, timeout=10)
    resp.raise_for_status()
    return resp.json()


if __name__ == "__main__":
    print(fetch_profile(sys.argv[1], sys.argv[2]))
