import yaml
from jinja2 import Environment, FileSystemLoader


def render(data):
    env = Environment(loader=FileSystemLoader("templates"))
    env.filters["full_load"] = yaml.full_load
    return env.get_template("page.html").render(data=data)
