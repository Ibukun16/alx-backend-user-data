#!/usr/bin/env python3
"""A SQLAlchemy model named User for a database table
named users by using the mapping declaration of SQLAlchemy
"""
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class User(Base):
    """User class that present a record from the user table
    """
    __tablename__ = 'users'

    # Define the column in the user table
    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)
