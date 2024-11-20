#!/usr/bin/env python3
"""Define a _hash_password method that takes in
a password string arguments and returns bytes.
"""
import bcrypt
from uuid import uuid4
from typing import Union, TypeVar
from sqlalchemy.orm.exc import NoResultFound

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Create a hashed password

    Args:
        password (str): string argument

    Return:
            bytes (str): Hashed password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initializing a new Authentication instance
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Method that register a new user to the database

        Args:
            email (str): user's email
            password (str): user's password

        Return:
                registered User
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
