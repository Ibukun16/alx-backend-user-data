#!/usr/bin/env python3
"""Module that handles the filtering of 
Personal data logs
"""

import os
import re
import logging
import mysql.connector
from typing import List


## PII filed to be redated
PII_FIELDS = ("name", "email", "phone", "ssn", "password")
match_pat = {
        'extract': lambda x, y: r'(?P<field>{})=[^{}]*'.format('|'.join(x), y),
        'replace': lambda x: r'\g<field>={}'.format(x),
        }


def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str,
        ) -> str:
    """
    Replaces sensitive information in a message with a redacted value
    based on the list of fields to redact

    Args:
        fields: list of fields to redact
        redaction: the value to use for redaction
        message: the string message to filter
        separator: the separator to use between fields

    Returns:
        The filtered log message with redacted values
    """
    extract, replace = (match_pat["extract"], match_pat["replace"])
    return re.sub(extract(field, separator), replace(redaction), message)


def get_logger() -> logging.Logger:
    """
    Get a Logger object for handling Personal Data

    Returns:
        A Logger object with INFO log level and RedactingFormatter
        formatter for filtering PII fields
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = ogging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(list(PII_FIELDS)))
    logger.addHandler(stream_handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Create a connector for accessing Personal Data from a database

    Returns:
        A MySQLConnection object using connection details from
        environment variables
    """
    host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME", "")
    username = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_pwd = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    conexn = mysql.connector.connection.MySQLConnection(
            host=host,
            port=3306,
            user=username,
            password=db_pwd,
            database=db_name,
            )
    return conexn


def main():
    """
    Main function that retrieves user data from the database
    and log to the console
    """
   fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fields.split(',')
    query = "SELECT {} FROM users;".format(fields)
    info_logger = get_logger()
    connection = get_db()
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            record = map(
                    lambda x: '{}={}'.format(x[0], x[1]),
                    zip(columns, row),
                    )
            msg = '{};'.format('; '.join(list(record)))
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_record = logging.LogRecord(*args)
            info_logger.handle(log_record)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    FORMAT_FIELDS = ('name', 'levelname', 'asctime', 'message')
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """formats a LogRecord.
        """
        msg = super(RedactingFormatter, self).format(record)
        txt = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return txt


if __name__ == "__main__":
    main()
