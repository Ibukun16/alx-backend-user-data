#!/usr/bin/envpython3
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
            for exclusive_path in map(lambda x: x.strip(), excluded_paths):
                pat_match = ''
                if exclusive_path[-1] == '*':
                    pat_match = '{}.*'.format(exclusive_path[0:-1])
                elif exclusive_path[-1] == '/':
                    pat_match ='{}/*'.format(exclusive_path[0:-1])
                else:
                    pat_match = '{}/*'.format(exclusive_path)
                if re.match(pat_match, path):
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

