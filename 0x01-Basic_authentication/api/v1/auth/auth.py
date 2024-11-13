#!/usr/bin/env python3
"""Authentication module for API
"""
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
            if path[-1] != '/':
                path += '/'
            for exclusive_path in excluded_paths:
                if exclusive_path.endswith('*'):
                    if exclusive_path.startswith(p[:1]):
                        return False
            return False if path in excluded_paths else True
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
