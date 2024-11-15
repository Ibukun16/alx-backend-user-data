#!/usr/bin/env python3
"""Authentication module for API
"""
import os
import re
from typing import List, TypeVar
from flask import request


class Auth:
    """Authentication class for Auth.

    Args:
        path (str): _description_
        excluded_paths (List[str]): _description_

    Returns:
            bool: _description_
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Checking if a path requires authentication.

        Args:
            path (str): _description_
            excluded_paths (List[str]): _description_

        Returns:
                bool: _description_
        """
        if path is not None and excluded_paths is not None:
            for exclude in map(lambda x: x.strip(), excluded_paths):
                fmt = ''
                if exclude[-1] == '*':
                    fmt = '{}.*'.format(exclude[0:-1])
                elif exclude[-1] == '/':
                    fmt = '{}/*'.format(exclude[0:-1])
                else:
                    fmt = '{}/*'.format(exclude)
                if re.match(fmt, path):
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """Get the authorization header field details from the request

        Args:
            request (_type_, optional): _description_. Defaults to None.

        Returns:
                str: _description_
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Get the current user details from the request
        """
        return None

    def session_cookie(self, request=None) -> str:
        """Get the value of the cookie named SESSION_NAME.
        """
        if request is not None:
            cookie_name = os.getenv('SESSION_NAME')
            return request.cookies.get(cookie_name)
        else:
            return None
