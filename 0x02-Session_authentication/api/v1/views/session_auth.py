#!/usr/bin/env python3
"""Module of session that authenticate user views
"""
import os
from typing import Tuple
from api.v1.views import app_views
from models.user import User
from flask import abort, jsonify, request


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_login() -> Tuple[str, int]:
    """
    define a login session

    POST /api/v1/auth_session/login
    Return:
      - JSON representation of a User object.
    """
    not_found_err = {"error": "no user found for this email"}
    email = request.form.get('email')
    password = request.form.get('password')
    if email is None or len(email.strip()) == 0:
        return jsonify({"error": "email missing"}), 400
    if password is None or len(password.strip()) == 0:
        return jsonify({"error": "password missing"}), 400
    try:
        users = User.search({'email': email})
    except Exception:
        return jsonify(not_found_err), 404
    if len(users) <= 0:
        return jsonify(not_found_err), 404
    if users[0].is_valid_password(password):
        from api.v1.app import auth
        session_id = auth.create_session(getattr(users[0], 'id'))
        resp = jsonify(users[0].to_json())
        session_name = os.getenv('SESSION_NAME')
        resp.set_cookie(session_name, session_id)
        return resp
    return jsonify({"error": "wrong password"}), 401


@app_views.route(
        '/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def logout():
    """user logouut session

    DELETE /api/v1/auth_session/logout
    Return:
      - An empty JSON object.
    """
    from api.v1.app import auth
    destroyed = auth.destroy_session(request)
    if not destroyed:
        abort(404)
    return jsonify({}), 200
