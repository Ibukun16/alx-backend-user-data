#!/usr/bin/env python3
"""new authentication class SessionDBAuth
that inherits from SessionExpAuth
"""
from flask import request
from datetime import datetime, timedelta
from models.user_session import UserSession
from api.v1.auth.session_exp_auth import SessionExpAuth


class SessionDBAuth(SessionExpAuth):
    """A class that authenticate a session with expiration
    and storage support
    """

    def create_session(self, user_id=None) -> str:
        """Create and store a session id for the user
        """
        if user_id:
            session_id = super().create_session(user_id)
            if isinstance(session_id, str):
                kwargs = {
                    'user_id': user_id,
                    'session_id': session_id,
                }
                user_session = UserSession(**kwargs)
                user_session.save_to_file()
            return session_id

    def user_id_for_session_id(self, session_id=None):
        """Retrieve the id of a user linked to a given session
        """
        UserSession.load_from_file()
        try:
            user_sesn = UserSession.search({'session_id': session_id})
        except Exception:
            return None
        if len(user_sesn) <= 0:
            return None
        current_time = datetime.now()
        time_duration = timedelta(seconds=self.session_duration)
        exp_time = user_sesn[0].created_at + time_span
        if exp_time < current_time:
            return None
        return user_sesn[0].user_id

    def destroy_session(self, request=None) -> bool:
        """Destroy a user session after completion
        based on the Session ID from the request cookie
        """
        if request:
            session_id = self.session_cookie(request)
        try:
            user_sesn = UserSession.search({'session_id': session_id})
        except Exception:
            return False
        if len(user_sesn) <= 0:
            return False
        user_sesn[0].remove()
        UserSession.save_to_file()
        return True
