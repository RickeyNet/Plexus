"""Where Plexus may send a shared secret: the one rule and its helpers.

Some actions send a stored secret to whatever device answers at an address:
unattended collection (monitoring polls, MAC tracking, topology walks,
scheduled backups and compliance scans, the FDM collector) signing in with
the Plexus service credential, the default credential or a shared SNMP
profile; a job whose template or inputs use secret variables; discovery
signing in with the service credential. A non-admin who may add or change
inventory hosts could otherwise point such an action at a device they run
and receive the secret.

The rule: **shared secrets go only to a host address that an admin set or
confirmed.** A host stores whether its address is confirmed
(``hosts.address_confirmed``): an address written by an admin or the
server API token is, one written by anyone else (or by a run nobody
configured) is not, until an admin confirms it
(``POST /api/admin/hosts/confirm-address``). Changing other host fields leaves
the flag as it is.

- ``address_confirmed`` / ``split_by_confirmation``: the per-host check the
  collection paths call before sending a shared secret; a skipped host is
  reported with ``ADDRESS_AWAITING_CONFIRMATION``, never recorded as down.
- ``credential_is_shared`` / ``may_send_credential``: the check for a path
  that is handed a credential (a user's own credential is not shared).

A user's own (personal) credential follows a second rule when the work runs
later for its stored owner rather than for the owner in the request (a
scheduled backup or compliance scan, a queued or approved job, a deployment
someone else runs): **a personal credential goes only to an address that an
admin confirmed or that its owner set.** A host stores who last wrote its
address (``hosts.address_set_by``, a user id; NULL when no signed-in user
did, and for hosts stored before it was recorded). The owner choosing a
target in the same request keeps sending their credential anywhere.

- ``may_send_credential(..., deferred=True)`` / ``send_refusal``: that check
  and the reason a skipped host is reported with.
- ``session_owns_credential``: whether a request's signed-in user owns the
  credential (their run is not deferred).
- ``address_writer_id``: the user recorded as having set an address a
  caller writes.
- ``recorded_address_refusal``: the same check for an address a run
  recorded earlier (an upgrade campaign device), on the host's row read now.
- ``unattended_credential``: the credential unattended collection signs in
  with (the service credential; the legacy default credential only when it
  is itself a service credential).
- ``caller_confirms_addresses``: whether an address a caller writes counts
  as confirmed.
- ``unmanaged_addresses``: for a request-supplied address, whether it is a
  confirmed inventory host the caller may change.
- ``same_address``: whether two address strings name the same address.
- ``name_hosts``: the hosts a path refused, as text for its message.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from typing import Any

import routes.database as db
from routes.db.change_events import current_actor

import netcontrol.routes.state as state
from netcontrol.account_rules import API_TOKEN_USER
from netcontrol.object_scope import readable_host_ids
from netcontrol.routes.shared import request_session, service_credential

# The reason a collection path gives for a host it skipped under this rule.
ADDRESS_AWAITING_CONFIRMATION = "address awaiting admin confirmation"
# The reason a deferred run gives for a host it skipped under the personal
# credential rule (it contains ADDRESS_AWAITING_CONFIRMATION: an admin's
# confirmation clears both).
ADDRESS_NOT_SET_BY_OWNER = f"{ADDRESS_AWAITING_CONFIRMATION}, and the credential's owner did not set it"


def _address_key(value: object) -> str:
    """``value`` as a comparable address: the canonical IP text, else the
    trimmed lower-case string (so ``2001:DB8::1`` matches ``2001:db8::1``)."""
    text = str(value or "").strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.lower()


def same_address(a: object, b: object) -> bool:
    """Whether ``a`` and ``b`` name the same address, whatever their
    spelling (``2001:DB8::1`` and ``2001:db8::1``)."""
    return _address_key(a) == _address_key(b)


def name_hosts(hosts: Iterable[Mapping[str, Any]], limit: int = 5) -> str:
    """The first ``limit`` of ``hosts`` as text for a message that says
    which hosts were skipped or refused: ``name (address)`` each, then
    ``and N more``."""
    rows = list(hosts)
    names = []
    for host in rows[:limit]:
        name = str(host.get("hostname") or "").strip()
        address = str(host.get("ip_address") or "").strip()
        names.append(f"{name} ({address})" if name and address else name or address or "unnamed host")
    shown = ", ".join(names)
    return f"{shown} and {len(rows) - limit} more" if len(rows) > limit else shown


def address_confirmed(host: Mapping[str, Any] | None) -> bool:
    """Whether an admin set or confirmed ``host``'s address. A host dict
    without the flag (not a row of the hosts table) is not confirmed."""
    if not host:
        return False
    try:
        return int(host.get("address_confirmed") or 0) == 1
    except TypeError, ValueError:
        return False


def split_by_confirmation[H: Mapping[str, Any]](hosts: Iterable[H]) -> tuple[list[H], list[H]]:
    """``(confirmed, awaiting)``: the hosts that may get shared secrets and
    the ones whose address awaits an admin's confirmation, order kept."""
    confirmed: list[H] = []
    awaiting: list[H] = []
    for host in hosts:
        (confirmed if address_confirmed(host) else awaiting).append(host)
    return confirmed, awaiting


def credential_is_shared(credential: Mapping[str, Any] | None) -> bool:
    """Whether ``credential`` is a shared secret: a Plexus service
    credential or the app-wide default credential (a user's own stored
    credential is not)."""
    if not credential:
        return False
    if credential.get("is_service"):
        return True
    default_id = state.AUTH_CONFIG.get("default_credential_id")
    cred_id = credential.get("id")
    return isinstance(default_id, int) and cred_id is not None and str(cred_id) == str(default_id)


def address_set_by_owner(host: Mapping[str, Any] | None, credential: Mapping[str, Any] | None) -> bool:
    """Whether ``host``'s current address was last written by the user who
    owns ``credential``. False when either is unknown (no recorded writer,
    an unowned credential)."""
    if not host or not credential:
        return False
    setter = host.get("address_set_by")
    owner = credential.get("owner_id")
    if setter is None or owner is None:
        return False
    try:
        return int(setter) == int(owner)
    except TypeError, ValueError:
        return False


def may_send_credential(
    host: Mapping[str, Any] | None, credential: Mapping[str, Any] | None, *, deferred: bool = False
) -> bool:
    """Whether ``credential`` may be sent to ``host``'s address: always for
    a confirmed address, never for a shared credential otherwise. A user's
    own credential may, except in ``deferred`` use (the work runs for the
    credential's stored owner, not for the owner in the request): then only
    to an address its owner set."""
    if address_confirmed(host):
        return True
    if credential_is_shared(credential):
        return False
    return not deferred or address_set_by_owner(host, credential)


def send_refusal(
    host: Mapping[str, Any] | None, credential: Mapping[str, Any] | None, *, deferred: bool = False
) -> str | None:
    """Why ``credential`` may not be sent to ``host``'s address
    (``may_send_credential``), as text that starts with which credential
    was held back, or None when it may."""
    if may_send_credential(host, credential, deferred=deferred):
        return None
    if credential_is_shared(credential):
        return f"Not signed in with the shared credential: {ADDRESS_AWAITING_CONFIRMATION}"
    return f"Not signed in with the owner's personal credential: {ADDRESS_NOT_SET_BY_OWNER}"


def session_owns_credential(session: Mapping[str, Any] | None, credential: Mapping[str, Any] | None) -> bool:
    """Whether the signed-in user of ``session`` owns ``credential``: work
    they start with it in this request is not deferred use. The server API
    token owns no credential."""
    if not session or not credential or session.get("auth_mode") == "token":
        return False
    user_id = session.get("user_id")
    owner = credential.get("owner_id")
    if user_id is None or owner is None:
        return False
    try:
        return int(user_id) == int(owner)
    except TypeError, ValueError:
        return False


async def recorded_address_refusal(
    host_id: int | None, address: str, credential: Mapping[str, Any] | None
) -> str | None:
    """Why ``credential`` may not be sent to ``address``, the address a run
    recorded for inventory host ``host_id`` (an upgrade campaign device),
    or None when it may. Decided on the host's stored row read now: a
    shared credential goes only to the host's confirmed address, so the
    host must still exist (``host_id`` None: it was deleted) and the
    recorded address must still be its address. A credential that is not
    shared is never refused."""
    if not credential_is_shared(credential):
        return None
    host = await db.get_host(int(host_id)) if host_id is not None else None
    if host is None:
        return "the inventory host no longer exists"
    if not address_confirmed(host):
        return ADDRESS_AWAITING_CONFIRMATION
    if not same_address(host.get("ip_address"), address):
        return "address differs from the inventory host's confirmed address"
    return None


async def unattended_credential() -> dict | None:
    """The credential unattended collection (monitoring, MAC tracking) signs
    in with: the Plexus service credential (``shared.service_credential``),
    else the legacy ``default_credential_id`` when that credential is itself
    a service credential. Never a user's personal credential."""
    credential = await service_credential()
    if credential is not None:
        return credential
    default_id = state.AUTH_CONFIG.get("default_credential_id")
    if not isinstance(default_id, int) or not default_id:
        return None
    fallback = await db.get_credential_raw(default_id)
    return fallback if fallback and fallback.get("is_service") else None


async def _actor_confirms_addresses() -> bool:
    """For a write with no request at hand: whether the acting user of this
    request (``current_actor``) is an admin or the server API token. A run
    with no actor (a background loop) confirms nothing. A user account named
    like the API token actor is judged by its role, never as the token."""
    actor = str(current_actor.get() or "").strip()
    if not actor:
        return False
    user = await db.get_user_by_username(actor)
    if user is not None:
        return user.get("role") == "admin"
    return actor == API_TOKEN_USER


async def caller_confirms_addresses(request: Any = None) -> bool:
    """Whether a host address written for this caller counts as confirmed:
    an admin session or the server API token. Without a request (or with
    one carrying no session) the acting user of the request decides
    (``current_actor``); a background run confirms nothing."""
    session = request_session(request) if request is not None else None
    if session is None:
        return await _actor_confirms_addresses()
    if session.get("auth_mode") == "token":
        return True
    user = await db.get_user_by_id(int(session.get("user_id") or 0))
    return bool(user and user.get("role") == "admin")


async def address_writer_id(request: Any = None) -> int | None:
    """The user recorded as having set a host address written for this
    caller (``hosts.address_set_by``): the signed-in user's id; None for the
    server API token. Without a request (or with one carrying no session)
    the acting user of the request (``current_actor``) decides; a run with
    no acting user records nobody."""
    session = request_session(request) if request is not None else None
    if session is None:
        actor = str(current_actor.get() or "").strip()
        if not actor:
            return None
        user = await db.get_user_by_username(actor)
        return int(user["id"]) if user is not None else None
    if session.get("auth_mode") == "token" or session.get("user_id") is None:
        return None
    try:
        return int(session["user_id"])
    except TypeError, ValueError:
        return None


async def unmanaged_addresses(addresses: Iterable[str], scope_or_request: Any) -> list[str]:
    """The entries of ``addresses`` that are not the primary IP address of
    an inventory host the caller (a request, or an ``ObjectScope``) may
    change and whose address an admin confirmed. Any confirmed inventory
    host counts for an unrestricted scope. Order and duplicates of
    ``addresses`` are kept; blanks are skipped. Callers skip this check for
    an admin, who may send secrets anywhere."""
    wanted = [str(a).strip() for a in addresses if str(a or "").strip()]
    if not wanted:
        return []
    writable = await readable_host_ids(scope_or_request, write=True)
    known = {
        _address_key(host.get("ip_address"))
        for host in await db.get_all_hosts()
        if host.get("ip_address") and address_confirmed(host) and (writable is None or int(host["id"]) in writable)
    }
    return [address for address in wanted if _address_key(address) not in known]
