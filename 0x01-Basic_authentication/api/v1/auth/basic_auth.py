#!/usr/bin/env python3
"""Basic authentication module for API using Basic auth
"""


import re
import base64
import binascii
from typing import Tuple, TypeVar
from api.v1.auth.auth import Auth

from models.user import User


class BasicAuth(Auth):
    """Authentication class for Basic auth.

    Args:
        authorization_header (str): _description_

    Returns:
            str: _description_
    """
    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """Extract the Base64 part of the Authorization header
        for a Basic Authentication.
        """
        if type(authorization_header) == str:
            pat = r'Basic (?P<token>.+)'
            match_field = re.fullmatch(pat, authorization_header.strip())
            if match_field is not None:
                return match_field.group('token')
        return None

    def decode_base64_authorization_header(self, base64_authorization: str,
                                           ) -> str:
        """Decode a base64-encoded authorization header

        Args:
            base64_authorization_header (str): _description_

        Returns:
                str: _description_
        """
        if isinstance(base64_authorization_header, str):
            try:
                rsp = base64.b64decode(base64_authorization_header,
                                       validate=True)
                return rsp.decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                return None


def extract_user_credentials(self, decode_base64_authorization_header: str,
                             ) -> Tuple[str, str]:
    """Extract user details from a base64-decoded authorization header
    that uses Basic authentication flow

    Args:
        self (_type_): _description_
    """
    if isinstance(decoded_base64_authorization_header, str):
        lnk = r'(?P<user>[^:]+):(?P<password>.+)'
        mch = re.fullmatch(lnk, decoded_base64_authorization_header.strip())
        if mch is not None:
            user = mch.group('user')
            password = mch.group('password')
            return user, password
        return None, None

    def user_object_from_credentials(self, user_email: str, user_pwd: str,
                                     ) -> TypeVar('User'):
        """Retrieves a user based on the user's authentication credentials.
        """
        if isinstance(user_email, str) and isinstance(user_pwd, str):
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Retrieves the user from a request.

        Args:
            self (_type_): _description_
        """
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)
