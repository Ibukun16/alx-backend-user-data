#!/usr/bin/env python3
"""Set up a basic flask app with user authentication feature
"""
from auth import Auth
from flask import Flask, jsonify, request, abort, redirect

AUTH = Auth()
app = Flask(__name__)


@app.route('/', methods=['GET'], strict_slashes=False)
def hello_index() -> str:
    """GET route index

    Returns:
            str: json{'message': 'Bienvenue'}
    """
    return jsonify({'message': 'Bienvenue'}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
