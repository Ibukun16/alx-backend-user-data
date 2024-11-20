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


def _generate_uuid() -> str:
    """Generate UUID

    Return:
            str: string output of the generated UUID
    """
    return str(uuid4())


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

    def valid_login(self, email: str, password: str) -> bool:
        """Method that validates user login

        Args:
            email (str): user's email
            password (str): user's password

        Return:
                True if matches password else False
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        return bcrypt.checkpw(password.encode("utf-8"), user.hashed_password)

    def create_session(self, email: str) -> str:
        """Create a new session for a user

        Args:
            email (str): email of user

        Return:
                str: string output of the session ID
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Retrieve the details of a user based on a given session ID

        Args:
            session_id (str): session id of user

        Returns:
            str: user email
        """
        user = None
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroy a completed session associated with a given user upon logout

        Args:
            user_id (int): user id
        """
        try:
            user = self._db.find_user_by(id=user_id)
            self._db.update_user(user.id, session_id=None)
        except NoResultFound:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """Generate password reset token for a given user

        Args:
            email (str): user email address

        Return:
                password rest token else Value error
        """
        try:
            user = self._db.find_user_by(email=email)
            token = _generate_uuid()
            self._db.update_user(user.id, reset_token=token)
            return token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """Method that update the user password from the
        password reset token

        Args:
            reset_token (str): generated token
            password (str): User password

        Return:
                User, else Value error and return None
        """
        user = None
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            user = None
        if user is None:
            raise ValueError()
        new_pwd_hash = _hash_password(password)
        self._db.update_user(user.id, hashed_password=new_pwd_hash,
                             reset_token=None)
