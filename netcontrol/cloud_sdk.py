"""Cloud SDK sessions and clients for the scheduled cloud pullers.

The flow-log and traffic-metric pullers (``netcontrol.routes.cloud_flow_pullers``,
``netcontrol.routes.cloud_metric_pullers``) used to build a boto3 session
(with an STS ``AssumeRole`` call), and an SDK client per region, on every
cycle, partly on the event loop. Here:

- ``build_boto3_session`` and ``boto3_client_config``: the one copy of the
  session and client settings both pullers use.
- ``aws_account``: one :class:`AwsAccountClients` per puller and account,
  cached (``client_cache.ClientCache``) and rebuilt when the account's
  ``auth_config`` changes, and every 45 minutes: before the temporary
  credentials of an assumed role run out, and so that credentials read
  from a file are read again. Its clients are built once per service and
  region.
- ``cached_sdk_client``: the same for one Azure or GCP SDK client.

Everything here blocks (imports, credential chains, STS): call it inside a
worker thread. boto3 sessions are not safe to use from two threads at once,
so a session is only touched under its own lock; the clients it builds are
thread-safe and shared.
"""

from __future__ import annotations

import importlib
import json
import threading
from collections.abc import Callable
from typing import Any

from netcontrol.client_cache import ClientCache, fingerprint
from netcontrol.telemetry import configure_logging

__all__ = [
    "AwsAccountClients",
    "aws_account",
    "aws_error_code",
    "aws_sdk_errors",
    "boto3_client_config",
    "build_boto3_session",
    "cached_sdk_client",
    "forget_account",
    "region_client",
    "sdk_available",
]

LOGGER = configure_logging("plexus.cloud_sdk")

# AssumeRole credentials last an hour by default (the pullers ask for no
# other duration): a role session is rebuilt well before that. Every other
# session and client is rebuilt as often, so a key file or profile changed
# on disk (which is not part of ``auth_config``) is read again within it.
ROLE_SESSION_MAX_AGE_SECONDS = 45 * 60
# A puller runs at least hourly; an account unused for longer is dropped.
_MAX_IDLE_SECONDS = 3 * 3600.0
# Error codes after which an account's cached session is rebuilt at once.
EXPIRED_CREDENTIAL_CODES = frozenset({"ExpiredToken", "ExpiredTokenException", "RequestExpired"})


def boto3_client_config() -> Any:
    """Timeouts and adaptive retries for every puller client."""
    from botocore.config import Config

    return Config(
        connect_timeout=10,
        read_timeout=60,
        retries={"max_attempts": 4, "mode": "adaptive"},
    )


def build_boto3_session(auth: dict, *, role_session_name: str) -> Any:
    """A boto3 session from an account's ``auth_config``: a profile, static
    keys, or the default chain; then ``AssumeRole`` into ``role_arn`` when
    one is set (``role_session_name`` unless the account names its own).
    Calls STS when it assumes a role."""
    import boto3

    kwargs: dict[str, Any] = {}
    if auth.get("profile_name"):
        kwargs["profile_name"] = str(auth["profile_name"])
    if auth.get("access_key_id"):
        kwargs["aws_access_key_id"] = str(auth["access_key_id"])
    if auth.get("secret_access_key"):
        kwargs["aws_secret_access_key"] = str(auth["secret_access_key"])
    if auth.get("session_token"):
        kwargs["aws_session_token"] = str(auth["session_token"])
    session = boto3.Session(**kwargs)

    role_arn = str(auth.get("role_arn") or "").strip()
    if role_arn:
        from botocore.config import Config

        sts = session.client(
            "sts",
            config=Config(
                connect_timeout=10,
                read_timeout=30,
                retries={"max_attempts": 2},
            ),
        )
        assume_args: dict[str, str] = {
            "RoleArn": role_arn,
            "RoleSessionName": str(auth.get("role_session_name") or role_session_name),
        }
        external_id = str(auth.get("external_id") or "").strip()
        if external_id:
            assume_args["ExternalId"] = external_id
        creds = sts.assume_role(**assume_args)["Credentials"]
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    return session


def region_client(account: Any, service: str, region: str) -> Any:
    """``account``'s ``service`` client for ``region`` with the puller
    settings (built once by ``AwsAccountClients``). Blocks."""
    return account.client(service, region_name=region, config=boto3_client_config())


def aws_error_code(exc: Exception) -> str:
    """The AWS error code of a botocore ``ClientError`` (``""`` for others)."""
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, dict) else None
    return str(error.get("Code") or "") if isinstance(error, dict) else ""


def aws_sdk_errors() -> tuple[type[Exception], type[Exception]]:
    """``(BotoCoreError, ClientError)``; ``ImportError`` without boto3. The
    first import of boto3 takes a while: call it in a thread."""
    import boto3  # noqa: F401 - the puller needs it, not only botocore
    from botocore.exceptions import BotoCoreError, ClientError

    return BotoCoreError, ClientError


def sdk_available(module: str) -> bool:
    """Whether the SDK ``module`` imports (call it in a thread: the first
    import is slow)."""
    try:
        importlib.import_module(module)
    except ImportError:
        return False
    return True


class AwsAccountClients:
    """The boto3 session of one account and the clients built from it.

    Quacks like a session for the pullers (``client(...)``,
    ``region_name``). Each client is built once per service and region,
    under the session's lock, and then shared (boto3 clients are
    thread-safe; sessions are not). ``config`` is taken from the first call
    for a service and region: the pullers always pass the same settings."""

    def __init__(self, session: Any) -> None:
        self._session = session
        self._clients: dict[tuple[str, str | None], Any] = {}
        self._lock = threading.Lock()
        home = getattr(session, "region_name", None)
        self.region_name: str | None = home if isinstance(home, str) else None

    def client(self, service_name: str, region_name: str | None = None, config: Any = None) -> Any:
        key = (service_name, region_name)
        with self._lock:
            client = self._clients.get(key)
            if client is None:
                client = self._session.client(service_name, region_name=region_name, config=config)
                self._clients[key] = client
            return client

    def close(self) -> None:
        with self._lock:
            clients = list(self._clients.values())
            self._clients.clear()
        for client in clients:
            _close_sdk_client(client)


def _close_sdk_client(value: Any) -> None:
    close = getattr(value, "close", None)
    if not callable(close):
        return
    try:
        close()
    except Exception as exc:  # noqa: BLE001 - closing is best effort
        LOGGER.debug("cloud sdk: closing a client failed: %s", type(exc).__name__)


# (purpose, account id) -> an AwsAccountClients or an Azure / GCP client.
_SDK_CLIENTS: ClientCache[Any] = ClientCache(
    "cloud_sdk",
    max_entries=128,
    max_idle_s=_MAX_IDLE_SECONDS,
    close=_close_sdk_client,
)


def _auth_fingerprint(auth: dict, builder: object) -> tuple[str, object]:
    """Every field of the account's ``auth_config`` (credentials and their
    targets), hashed, and the builder itself: any change builds anew."""
    return fingerprint(json.dumps(auth, sort_keys=True, default=str)), builder


def aws_account(purpose: str, account_id: int, auth: dict, build_session: Callable[[dict], Any]) -> AwsAccountClients:
    """The cached ``AwsAccountClients`` of ``account_id`` for one puller
    (``purpose``), built with ``build_session(auth)`` when missing, when
    ``auth`` changed, or when it is ``ROLE_SESSION_MAX_AGE_SECONDS`` old.
    Blocks: call it in a worker thread."""
    account: AwsAccountClients = _SDK_CLIENTS.get(
        (purpose, "aws", int(account_id)),
        _auth_fingerprint(auth, build_session),
        lambda: AwsAccountClients(build_session(auth)),
        max_age_s=ROLE_SESSION_MAX_AGE_SECONDS,
    )
    return account


def cached_sdk_client[T](purpose: str, account_id: int, auth: dict, build: Callable[[], T], *, builder: object) -> T:
    """One Azure or GCP SDK client of ``account_id`` for one puller
    (``purpose``), built with ``build()`` when missing or when ``auth`` (or
    ``builder``, the function ``build`` calls) changed, or when it is
    ``ROLE_SESSION_MAX_AGE_SECONDS`` old. Blocks: call it in a worker
    thread."""
    client: T = _SDK_CLIENTS.get(
        (purpose, "sdk", int(account_id)),
        _auth_fingerprint(auth, builder),
        build,
        max_age_s=ROLE_SESSION_MAX_AGE_SECONDS,
    )
    return client


def forget_account(purpose: str, account_id: int) -> None:
    """Drop the cached session and clients of ``account_id`` for one puller
    (expired credentials), so the next cycle builds them again."""
    _SDK_CLIENTS.discard(lambda key: isinstance(key, tuple) and key[0] == purpose and key[2] == int(account_id))
