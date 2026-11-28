"""Database errors that are the caller's mistake.

A number past the column's range, a reference to a record that does not
exist and a value that must be unique are refused by the driver or by
PostgreSQL. ``client_error_for`` names the HTTP answer for those; every other
database error stays a server error. The messages are general on purpose:
table, column and constraint names are logged, not returned.
"""

from __future__ import annotations

from typing import NamedTuple

import asyncpg


class ClientError(NamedTuple):
    status: int
    code: str
    message: str


OUT_OF_RANGE = ClientError(422, "validation_error", "A value in the request is out of range")
DUPLICATE = ClientError(409, "http_error", "A record with the same value already exists")
# One answer for both directions of a foreign key: a parent that does not
# exist (insert, update) and a record other records still point at (delete).
REFERENCE = ClientError(409, "http_error", "The request refers to a record that does not exist or is still in use")
# A time bound PostgreSQL cannot read, against a TIMESTAMPTZ column.
BAD_TIME = ClientError(422, "validation_error", "A time in the request is not a valid timestamp")

# Reported by PostgreSQL for a value the column or the date arithmetic cannot hold.
_SERVER_OUT_OF_RANGE = (
    asyncpg.NumericValueOutOfRangeError,
    asyncpg.DatetimeFieldOverflowError,
    asyncpg.IntervalFieldOverflowError,
)
# The class the driver uses for a refused argument differs between its versions.
_DRIVER_ARGUMENT_ERRORS = (asyncpg.DataError, asyncpg.InterfaceError)


def client_error_for(exc: BaseException | None) -> ClientError | None:
    """The client error ``exc`` stands for, or ``None`` when it is a server
    error."""
    if isinstance(exc, asyncpg.UniqueViolationError):
        return DUPLICATE
    if isinstance(exc, asyncpg.ForeignKeyViolationError):
        return REFERENCE
    if isinstance(exc, _SERVER_OUT_OF_RANGE):
        return OUT_OF_RANGE
    if isinstance(exc, asyncpg.InvalidDatetimeFormatError):
        return BAD_TIME
    # The driver refuses an argument before sending it ("invalid input for
    # query argument"). An integer past int32/int64 has an OverflowError as
    # its cause; a wrong type (a TypeError) is a bug in the query's caller.
    if isinstance(exc, _DRIVER_ARGUMENT_ERRORS) and isinstance(exc.__cause__, OverflowError):
        return OUT_OF_RANGE
    return None
