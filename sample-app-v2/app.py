"""Intentionally vulnerable LAB sample app (old deps). Never deploy."""
from flask import Flask, request
app = Flask(__name__)
@app.route("/")
def hi():
    return "hello " + request.args.get("name", "lab")  # reflected, no escaping (lab)
