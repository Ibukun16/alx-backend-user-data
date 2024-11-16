#!/usr/bin/env python3
"""A new model of UserSession that inherits from Base
"""
from models.base import Base


class UserSession(Base):
    """User session class.
    """

    def __init__(self, *args: list, **kwargs: dict):
        """Initializes an instance of User session.
        """
        super().__init__(*args, **kwargs)
        self.user_id = kwargs.get('user_id')
        self.session_id = kwargs.get('session_id')
