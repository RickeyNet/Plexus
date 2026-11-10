"""Why an optional AWS discovery section was not collected.

The collector records a section it could not read as a ``collection_warning``
with the AWS error code (never the message: it can quote the request). The
code alone says what an admin can do about it:

  - ``permission``: AWS refused the call; an IAM action is missing from the
    account's policy
  - ``unavailable``: the service does not exist or is not enabled in that
    region (an opt-in region, a service not launched there), or the AWS SDK
    on the Plexus server is too old to know the service or the call
  - ``error``: anything else (throttling, a timeout, an AWS-side failure)

Pure: no boto3 import, so warnings stored by older discoveries are
classified the same way when the map is built.
"""

from __future__ import annotations

PERMISSION = "permission"
UNAVAILABLE = "unavailable"
FAILED = "error"

_PERMISSION_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "AuthFailure",
        "AuthorizationError",
        "AuthorizationErrorException",
        "Forbidden",
        "ForbiddenException",
        "NotAuthorized",
        "UnauthorizedAccess",
        "UnauthorizedException",
        "UnauthorizedOperation",
    }
)
_UNAVAILABLE_CODES = frozenset(
    {
        # No endpoint for the service in the region, or the region is not enabled.
        "EndpointConnectionError",
        "UnknownEndpoint",
        "OptInRequired",
        "UnrecognizedClientException",
        "InvalidClientTokenId",
        "SubscriptionRequiredException",
        "InvalidAction",
        "UnsupportedOperation",
        # The botocore on the server does not know the service or the call.
        "UnknownServiceError",
        "DataNotFoundError",
        "OperationNotInSdk",
    }
)


class OperationNotInSdk(Exception):  # noqa: N818 - its name is the error code recorded
    """The installed botocore has no such operation (an SDK older than the call)."""


def failure_category(code: str) -> str:
    """``permission``, ``unavailable`` or ``error`` for an AWS error code (or
    the exception type ``error_code`` falls back to)."""
    text = str(code or "").strip()
    # EC2 prefixes some codes with the side at fault: ``Client.UnauthorizedOperation``.
    bare = text.rsplit(".", 1)[-1]
    if text in _PERMISSION_CODES or bare in _PERMISSION_CODES:
        return PERMISSION
    if text in _UNAVAILABLE_CODES or bare in _UNAVAILABLE_CODES:
        return UNAVAILABLE
    return FAILED
