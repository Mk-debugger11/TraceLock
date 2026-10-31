import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    return str(yaml.load(request.data))
