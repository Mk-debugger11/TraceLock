import sys

from PIL import Image, ImageMath


def apply_expression(path, expr):
    img = Image.open(path).convert("L")
    out = ImageMath.eval(expr, a=img)
    return out.convert("L")


if __name__ == "__main__":
    apply_expression(sys.argv[1], sys.argv[2]).save(sys.argv[3])
