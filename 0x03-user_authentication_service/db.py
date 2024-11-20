#!/usr/bin/env python3
"""DB module
"""
from typing import TypeVar
from user import Base, User
from sqlalchemy import create_engine, tuple_
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.ext.declarative import declarative_base


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """DB class that implements the add_user method

        Args:
            email (string): email of user
            hashed_password (string): password of user
        Returns:
            User: user created
        """
        try:
            new_user = User(email=email, hashed_password=hashed_password)
            # add new user and commit to database
            self._session.add(new_user)
            self._session.commit()
        except Exception:
            self._session.rollback()
            new_user = None
        return new_user

    def find_user_by(self, **kwargs) -> User:
        """Method that finds a user by taking arbitrary
        keyword arguments and returns the firstrow found in
        the users table as filtered by the method’s input arguments

        Args:
            User (**kwargs): description

        Returns:
            User: found user or raise error
        """
        fields, values = [], []
        for key, val in kwargs.items():
            if hasattr(User, key):
                fields.append(getattr(User, key))
                values.append(val)
            else:
                raise InvalidRequestError()
        user = self._session.query(User).filter(tuple_(*fields).in_(
            [tuple(values)])).first()
        if not user:
            raise NoResultFound()
        return user

    def update_user(self, user_id: int, **kwargs) -> None:
        """Method that update user by taking as argument a required user_id
        integer and arbitrary keyword arguments, and returns None. Method
        uses find_user_by to locate the user to update, then update the user’s
        attributes as passed in the method’s arguments and commit changes to
        the database.

        Args:
            User_id (int): id of user
        """
        user = self.find_user_by(id=user_id)
        if user is None:
            return
        update_datasrc = {}
        for key, val in kwargs.items():
            if hasattr(User, key):
                update_datasrc[getattr(User, key)] = val
            else:
                raise ValueError
        self._session.query(User).filter(User.id == user_id).update(
                update_datasrc, synchronize_session=False)
        self._session.commit()
        return None
