import sys

from PIL import Image


def make_thumbnail(src, dst, width=128, height=128):
    thumb = Image.open(src).resize((width, height))
    thumb.save(dst)


if __name__ == "__main__":
    make_thumbnail(sys.argv[1], sys.argv[2])
