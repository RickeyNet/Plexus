"""Syslog over TCP (RFC 6587) and TLS (RFC 5425).

The UDP syslog receiver (``netcontrol/routes/metrics_engine.py``) takes any
datagram whose source address passes the listener allowlist, and a UDP
source address can be forged. A TCP connection cannot be opened from a
forged address (the handshake needs the reply), and a TLS connection with
a client certificate required proves which device sent it. Each transport
has its own :class:`StreamListener`; ``metrics_engine`` creates both, hands
every message to the same parser as UDP (``handle_syslog_message``, with
the transport recorded on the stored row) and starts, stops and rebinds
them from ``state.EVENT_RECEIVER_CONFIG``.

- **Framing** (:class:`FrameDecoder`): detected per frame, so one
  connection may mix them. A frame that starts with a digit is octet
  counted (``<length> <message>``); any other frame ends at LF (CRLF and
  NUL are accepted too). A frame longer than ``MAX_FRAME_BYTES``, a bad
  octet count or an unterminated line longer than that closes the
  connection (counted as an error). Nothing is buffered beyond one frame.
- **Sources**: the syslog listener's :class:`~netcontrol.listener_sources.
  SourceGuard`. A source the allowlist refuses is closed at accept (a
  ``source`` drop of the syslog listener); every message then passes
  ``admit``, so the per-source rate limit and its counters apply as for UDP.
- **Limits**: at most ``MAX_CONNECTIONS`` open connections and
  ``MAX_CONNECTIONS_PER_SOURCE`` per source address (a connection over
  either is closed and counted in ``refused``), a TLS handshake timeout and
  TCP keepalive on every accepted socket. There is no idle timeout: a
  device keeps one syslog connection open for days and may send nothing
  for hours, and keepalive finds the dead ones.
- **Accepting**: the listener accepts connections itself (``sock_accept``),
  checks the allowlist and the limits, and only then hands the socket to
  the event loop (``connect_accepted_socket``), with the TLS context for
  the TLS listener. A refused source so costs no handshake, and the
  handshake is the event loop's own from the first byte: upgrading an
  accepted stream (``start_tls``) loses the ClientHello under uvloop,
  which reads it before the upgrade runs.
- **Peer check**: a listener started with a ``peer_check`` calls it once per
  connection after the TLS handshake, before reading, with the source
  address and the peer certificate. A refusal closes the connection unread
  and is counted in ``cert_refused``. ``metrics_engine`` supplies it (the
  certificate must name the inventory host); this module knows neither.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import socket
import ssl
import time
from collections.abc import Callable, Iterator
from typing import Any

from netcontrol import listener_sources

LOGGER = logging.getLogger("plexus.syslog_stream")

TRANSPORTS: tuple[str, ...] = ("tcp", "tls")
LABELS = {"tcp": "syslog TCP", "tls": "syslog TLS"}
# Parses and queues one message: (frame, source address).
Handler = Callable[[bytes, str], None]
# Checks a connection after the TLS handshake: (source address, peer
# certificate as ``getpeercert()`` gives it, None without one) -> "" to
# accept, else the reason to close it.
PeerCheck = Callable[[str, dict | None], str]

# The longest frame accepted (RFC 6587 / RFC 5425 receivers must take at
# least 2048 octets; devices send far less).
MAX_FRAME_BYTES = 8192
MAX_CONNECTIONS = 1024
MAX_CONNECTIONS_PER_SOURCE = 8
TLS_HANDSHAKE_TIMEOUT_SECONDS = 10.0
LISTEN_BACKLOG = 128
# The wait before accepting again after an accept error (out of file
# descriptors, for one), so a persistent error is no busy loop.
ACCEPT_RETRY_SECONDS = 1.0

_TERMINATOR = re.compile(rb"[\n\x00]")
_SEPARATORS = b"\r\n\x00"


class FramingError(ValueError):
    """The byte stream is not RFC 6587 framed syslog; the connection is closed."""


class FrameDecoder:
    """Split a syslog byte stream into messages (RFC 6587), the framing
    detected per frame. ``feed`` keeps at most one partial frame."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> Iterator[bytes]:
        """The complete frames in what has arrived so far, in order. Raises
        :class:`FramingError` (after yielding the frames before it) on an
        over-long frame or a bad octet count."""
        buf = self._buffer
        buf += data
        while True:
            start = 0
            while start < len(buf) and buf[start] in _SEPARATORS:
                start += 1
            if start:
                del buf[:start]
            if not buf:
                return
            frame = self._octet_counted() if 0x30 <= buf[0] <= 0x39 else self._line()
            if frame is None:
                return
            if frame:
                yield frame

    def _octet_counted(self) -> bytes | None:
        buf = self._buffer
        digits = len(str(MAX_FRAME_BYTES))
        space = buf.find(b" ", 0, digits + 1)
        head = bytes(buf[: space if space >= 0 else digits + 1])
        if not head.isdigit():
            raise FramingError("bad octet count")
        if space < 0:
            if len(buf) > digits:
                raise FramingError("octet count too long")
            return None
        length = int(head)
        if length == 0 or length > MAX_FRAME_BYTES:
            raise FramingError(f"octet count {length} out of range")
        end = space + 1 + length
        if len(buf) < end:
            return None
        frame = bytes(buf[space + 1 : end])
        del buf[:end]
        return frame

    def _line(self) -> bytes | None:
        buf = self._buffer
        found = _TERMINATOR.search(buf)
        if found is None:
            if len(buf) > MAX_FRAME_BYTES:
                raise FramingError("unterminated line longer than the frame limit")
            return None
        end = found.start()
        if end > MAX_FRAME_BYTES:
            raise FramingError("line longer than the frame limit")
        frame = bytes(buf[:end]).rstrip(b"\r")
        del buf[: end + 1]
        return frame


def _listening_socket(host: str, port: int) -> socket.socket:
    """A non-blocking TCP socket listening on ``host``:``port``. Raises
    ``OSError`` when the port will not bind."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        # As asyncio's own servers: a restart must not wait out TIME_WAIT.
        # Not on Windows, where the option lets a second socket take a port
        # that is in use.
        if os.name == "posix":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(LISTEN_BACKLOG)
        sock.setblocking(False)
    except OSError:
        sock.close()
        raise
    return sock


def _keepalive(conn: socket.socket) -> None:
    try:
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError as exc:
        LOGGER.debug("syslog stream: keepalive not set: %s", exc)


class StreamListener:
    """One TCP or TLS syslog listener. ``handler(frame, source_ip)`` parses
    and queues a message; ``stats`` (received, errors, last_message_at,
    started_at, ``reset``) counts since the listener last started."""

    def __init__(self, transport: str, handler: Handler, stats: Any) -> None:
        self.transport = transport
        self.label = LABELS.get(transport, transport)
        self.stats = stats
        self._handler = handler
        self._guard = listener_sources.guard("syslog")
        # The listening socket; None while stopped.
        self._server: socket.socket | None = None
        self._accept_task: asyncio.Task | None = None
        self._ssl: ssl.SSLContext | None = None
        # The task serving each open connection (from its accept on, so a
        # handshake in progress counts) and the address it came from.
        self._connections: dict[asyncio.Task, str] = {}
        self._per_source: dict[str, int] = {}
        self.port = 0
        # What the running listener was started with (the TLS material and
        # its client certificate mode); a change rebinds it.
        self.config_key = ""
        # Why the enabled listener is not running ("" when it is).
        self.error = ""
        self.refused = 0
        # Connections closed after the handshake because ``peer_check`` refused them.
        self.cert_refused = 0
        self._peer_check: PeerCheck | None = None

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def connections(self) -> int:
        return len(self._connections)

    async def start(
        self,
        host: str,
        port: int,
        ssl_context: ssl.SSLContext | None = None,
        config_key: str = "",
        peer_check: PeerCheck | None = None,
    ) -> bool:
        """Listen on ``host``:``port``. True when it is (already) listening;
        a failed bind is logged, kept in ``error`` and returns False.
        ``peer_check`` (see :data:`PeerCheck`) vets each connection before
        anything is read from it."""
        if self._server is not None:
            return True
        try:
            sock = _listening_socket(host, port)
        except OSError as exc:
            self.error = f"Could not listen on TCP port {port}: {exc}"
            LOGGER.warning("metrics: failed to start %s receiver on TCP port %d: %s", self.label, port, exc)
            return False
        self._server = sock
        self._ssl = ssl_context
        self._peer_check = peer_check
        self.port = port
        self.config_key = config_key
        self.error = ""
        self.refused = 0
        self.cert_refused = 0
        self.stats.reset(time.time())
        self._accept_task = asyncio.get_running_loop().create_task(self._accept_loop(sock))
        # The source allowlist needs the inventory addresses from the first connection.
        await listener_sources.refresh_inventory()
        LOGGER.info("metrics: %s receiver started on TCP port %d", self.label, port)
        return True

    def stop(self) -> bool:
        """Close the listener and every open connection. True when it was running."""
        sock = self._server
        if sock is None:
            return False
        accept_task, self._accept_task = self._accept_task, None
        self._server = None
        self.port = 0
        self.config_key = ""
        # A listener whose event loop is already closed (tests) has no task
        # left to cancel. The accept is cancelled before its socket closes;
        # each connection closes as its task ends.
        if accept_task is not None and not accept_task.get_loop().is_closed():
            accept_task.cancel()
            for task in list(self._connections):
                task.cancel()
        sock.close()
        self._connections.clear()
        self._per_source.clear()
        LOGGER.info("metrics: %s receiver stopped", self.label)
        return True

    def _accept(self, source_ip: str) -> bool:
        if not self._guard.allow_source(source_ip):
            return False
        if len(self._connections) >= MAX_CONNECTIONS:
            LOGGER.debug("%s: connection limit reached, refusing %s", self.label, source_ip)
            return False
        if self._per_source.get(source_ip, 0) >= MAX_CONNECTIONS_PER_SOURCE:
            LOGGER.debug("%s: per-source connection limit reached, refusing %s", self.label, source_ip)
            return False
        return True

    async def _accept_loop(self, sock: socket.socket) -> None:
        """Accept until the listener stops (``stop`` cancels this task). A
        refused connection is closed before anything is read from it."""
        loop = asyncio.get_running_loop()
        while True:
            try:
                conn, peer = await loop.sock_accept(sock)
            except OSError as exc:
                LOGGER.warning("metrics: %s receiver could not accept a connection: %s", self.label, exc)
                await asyncio.sleep(ACCEPT_RETRY_SECONDS)
                continue
            source_ip = str(peer[0])
            if not self._accept(source_ip):
                self.refused += 1
                conn.close()
                continue
            task = loop.create_task(self._serve(conn, source_ip))
            self._connections[task] = source_ip
            self._per_source[source_ip] = self._per_source.get(source_ip, 0) + 1

    async def _open(self, conn: socket.socket) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """The streams of an accepted socket, after the TLS handshake on the
        TLS listener (the event loop reads the handshake itself)."""
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(loop=loop)
        protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
        if self._ssl is None:
            transport, _ = await loop.connect_accepted_socket(lambda: protocol, conn)
        else:
            transport, _ = await loop.connect_accepted_socket(
                lambda: protocol, conn, ssl=self._ssl, ssl_handshake_timeout=TLS_HANDSHAKE_TIMEOUT_SECONDS
            )
        return reader, asyncio.StreamWriter(transport, protocol, reader, loop)

    async def _serve(self, conn: socket.socket, source_ip: str) -> None:
        task = asyncio.current_task()
        writer: asyncio.StreamWriter | None = None
        try:
            _keepalive(conn)
            try:
                reader, writer = await self._open(conn)
            except (OSError, ssl.SSLError, TimeoutError) as exc:
                self.stats.errors += 1
                LOGGER.debug("%s: connection from %s not set up: %s", self.label, source_ip, exc)
                return
            if self._peer_check is not None:
                reason = self._peer_check(source_ip, writer.get_extra_info("peercert"))
                if reason:
                    self.cert_refused += 1
                    LOGGER.debug("%s: closing the connection from %s: %s", self.label, source_ip, reason)
                    return
            await self._read(reader, source_ip)
        except FramingError as exc:
            self.stats.errors += 1
            LOGGER.debug("%s: closing the connection from %s: %s", self.label, source_ip, exc)
        except (OSError, ssl.SSLError) as exc:
            LOGGER.debug("%s: connection from %s ended: %s", self.label, source_ip, exc)
        finally:
            if task is not None:
                self._release(task, source_ip)
            try:
                if writer is not None:
                    writer.close()
                else:
                    conn.close()  # never handed over, or the hand-over failed
            except RuntimeError:
                pass  # its event loop is already closed

    def _release(self, task: asyncio.Task, source_ip: str) -> None:
        if self._connections.pop(task, None) is None:
            return  # the listener stopped (and maybe restarted) meanwhile
        left = self._per_source.get(source_ip, 0) - 1
        if left > 0:
            self._per_source[source_ip] = left
        else:
            self._per_source.pop(source_ip, None)

    async def _read(self, reader: asyncio.StreamReader, source_ip: str) -> None:
        decoder = FrameDecoder()
        while True:
            data = await reader.read(MAX_FRAME_BYTES)
            if not data:
                return
            for frame in decoder.feed(data):
                self._message(frame, source_ip)

    def _message(self, frame: bytes, source_ip: str) -> None:
        if not self._guard.admit(source_ip):
            return
        stats = self.stats
        stats.received += 1
        stats.last_message_at = time.time()
        try:
            self._handler(frame, source_ip)
        except Exception as exc:  # noqa: BLE001 - one bad message must not close the connection
            stats.errors += 1
            LOGGER.debug("%s: parse error from %s: %s", self.label, source_ip, exc)
