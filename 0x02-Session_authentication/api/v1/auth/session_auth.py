#!/usr/bin/env python3
"""Authentication module for API using Session
"""
from uuid import uuid4
from flask import request
from models.user import User
from api.v1.auth.auth import Auth


class SessionAuth(Auth):
    """Authentication class for Session
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Create session id for the user

        Args:
            user_id (str, optional): _description_. Defaults to None.

        Returns:
            str: session id
        """
        if user_id is None:
            return None
        if isinstance(user_id, str):
            session_id = str(uuid4())
            self.user_id_by_session_id[session_id] = user_id
            return session_id
        else:
            return None

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """define the user id for the user session

        Args:
            session_id (str, optional): _description_. Defaults to None.

        Returns:
                str: user id based on the session
        """
        if session_id is None:
            return None
        if isinstance(session_id, str):
            return self.user_id_by_session_id.get(session_id)
        else:
            return None

    def current_user(self, request=None) -> User:
        """current user

        Args:
            session_id (_type_, optional): _description_. Defaults to None.

            Returns:
                str: details of the current user
        """
        session_cookie = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_cookie)
        user = User.get(user_id)
        return user

    def destroy_session(self, request=None):
        """Destroy the current session upon completion

        Args:
            session_id (_type_, optional): _description_. Defaults to None.

            Returns:
                str: the session id for the user
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        if (request is None or session_id is None) or user_id is None:
            return False
        if session_id in self.user_id_by_session_id:
            del self.user_id_by_session_id[session_id]
        return True
