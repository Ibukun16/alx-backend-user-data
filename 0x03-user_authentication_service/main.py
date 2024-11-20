#!/usr/bin/env python3
"""Main module that run end-to-end (E2E)
integration test for app.py
"""
import requests


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"
BASE_URL = "http://0.0.0.0:5000"


def register_user(email: str, password: str) -> None:
    """A function that test for registering a user
    """
    url = f"{BASE_URL}/users"
    body = {'email': email, 'password': password}
    resp = requests.post(url, data=body)
    assert resp.status_code == 200
    assert resp.json() == {"email": email, "message": "user created"}
    resp = requests.post(url, data=body)
    assert resp.status_code == 400
    assert resp.json() == {"message": "email already registered"}


def log_in_wrong_password(email: str, password: str) -> None:
    """A  function that test wrong log in
    """
    url = f"{BASE_URL}/sessions"
    body = {'email': email, 'password': password}
    resp = requests.post(url, data=body)
    assert resp.status_code == 401


def log_in(email: str, password: str) -> str:
    """A function that test for correct log in
    """
    url = f"{BASE_URL}/sessions"
    body = {'email': email, 'password': password}
    resp = requests.post(url, data=body)
    assert resp.status_code == 200
    assert resp.json() == {"email": email, "message": "logged in"}
    return resp.cookies.get('session_id')


def profile_unlogged() -> None:
    """A function that test retrieving
    profile information whilst logged out
    """
    url = f"{BASE_URL}/profile"
    resp = requests.get(url)
    assert resp.status_code == 403


def profile_logged() -> None:
    """A function that test retrieving
    profile information whilst logged out
    """
    url = f"{BASE_URL}/profile"
    cookies = {'session_id': session_id}
    resp = requests.get(url, cookies=cookies)
    assert resp.status_code == 200
    assert "email" in resp.json()


def log_out(session_id: str) -> None:
    """A function that tests logging out of a session
    """
    url = f"{BASE_URL}/sessions"
    cookies = {'session_id': session_id}
    resp = requests.delete(url, cookies=cookies)
    assert resp.status_code == 200
    assert resp.json() == {"message": "Bienvenue"}


def reset_password_token(email: str) -> str:
    """A function that test requesting a password reset
    """
    url = f"{BASE_URL}/reset_password"
    body = {'email': email}
    resp = requests.post(url, data=body)
    assert resp.status_code == 200
    assert "email" in resp.json()
    assert resp.json()["email"] == email
    assert "reset_token" in resp.json()
    return resp.json().get('reset_token')


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """A function that test updating user password
    """
    url = f"{BASE_URL}/reset_password"
    body = {'email': email,
            'reset_token': reset_token,
            'new_password': new_password}
    resp = requests.put(url, data=body)
    assert resp.status_code == 200
    assert resp.json() == {"email": email, "message": "Password updated"}


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
