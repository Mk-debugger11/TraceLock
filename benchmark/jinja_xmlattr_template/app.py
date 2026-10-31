import sys

from jinja2 import Environment, FileSystemLoader


def render_profile(user_attrs):
    env = Environment(loader=FileSystemLoader("templates"), autoescape=True)
    return env.get_template("page.html").render(attrs=user_attrs)


if __name__ == "__main__":
    pairs = (arg.split("=", 1) for arg in sys.argv[1:])
    print(render_profile({key: value for key, value in pairs}))
