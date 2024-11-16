#!/usr/bin/env python3
"""A module that authenticate session with an expiration for API
"""
from os import getenv
from flask import request
from datetime import datetime, timedelta
from api.v1.auth.session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """class to manage API authentication with expiration
    """

    def __init__(self) -> None:
        """Initializing a new instance of SessionExpAuth
        """
        super().__init__()
        try:
            self.session_duration = int(getenv('SESSION_DURATION', '0'))
        except Exception:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """Create the user session id
        """
        session_id = super().create_session(user_id)
        if not isinstance(session_id, str):
            return None
        self.user_id_by_session_id[session_id] = {
                'user_id': user_id,
                'created_at': datetime.now(),
        }
        return session_id

    def user_id_for_session_id(self, session_id=None) -> str:
        """Retrieves the user id of the user associated with
        a given session id.
        """
        if session_id is None:
            return None
        if session_id in self.user_id_by_session_id:
            session_dict = self.user_id_by_session_id[session_id]
            if self.session_duration <= 0:
                return session_dict['user_id']
            if 'created_at' not in session_dict:
                return None
            current_time = datetime.now()
            time_duration = timedelta(seconds=self.session_duration)
            expiratn_time = session_dict['created_at'] + time_duration
            if expiratn_time < current_time:
                return None
            return session_dict['user_id']
        else:
            return None
