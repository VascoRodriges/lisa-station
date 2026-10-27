"""Pinned SSH, one fixed read-only command, and bounded response buffers."""

from __future__ import annotations

import asyncio
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

import asyncssh

from .const import STATUS_COMMAND
from .protocol import FoundationStatus, ProtocolError, parse_status


class StationError(Exception):
    """A station request failed; messages contain no connection credentials."""


class AuthenticationError(StationError):
    """The dedicated key is unreadable or rejected."""


class HostKeyError(StationError):
    """The server did not match its configured public key."""


class InvalidConfiguration(StationError):
    """Connection settings are invalid."""


@dataclass(frozen=True)
class ConnectionSettings:
    """A host-specific SSH identity. Private key contents are never stored here."""

    host: str = field(repr=False)
    port: int
    username: str = field(repr=False)
    private_key_file: str = field(repr=False)
    server_host_key: str = field(repr=False)

    def validated(self) -> ConnectionSettings:
        """Reject host-pattern injection and normalize exactly one public key."""
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", self.host):
                raise InvalidConfiguration("invalid_host") from None
        if any(character.isspace() for character in self.host) or "%" in self.host:
            raise InvalidConfiguration("invalid_host")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise InvalidConfiguration("invalid_port")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.username):
            raise InvalidConfiguration("invalid_username")
        if not PurePosixPath(self.private_key_file).is_absolute() or "\x00" in self.private_key_file:
            raise InvalidConfiguration("invalid_key_path")
        if "\n" in self.server_host_key.strip() or "\r" in self.server_host_key.strip():
            raise InvalidConfiguration("invalid_host_key")
        try:
            public_key = asyncssh.import_public_key(self.server_host_key)
        except (ValueError, asyncssh.KeyImportError):
            raise InvalidConfiguration("invalid_host_key") from None
        return ConnectionSettings(
            self.host,
            self.port,
            self.username,
            self.private_key_file,
            public_key.export_public_key().decode().strip(),
        )

    @property
    def unique_id(self) -> str:
        """Pin device identity to its verified SSH host key, independent of IP."""
        return asyncssh.import_public_key(self.server_host_key).get_fingerprint("sha256")


async def _read_bounded(reader, limit: int) -> bytes:
    buffer = bytearray()
    while True:
        part = await reader.read(min(1024, limit + 1 - len(buffer)))
        if not part:
            return bytes(buffer)
        buffer.extend(part)
        if len(buffer) > limit:
            raise ProtocolError("response_too_large")


class StationClient:
    """No shell input, password fallback, SSH-agent use or host-key bypass."""

    def __init__(self, settings: ConnectionSettings) -> None:
        self.settings = settings.validated()

    async def read_status(self) -> FoundationStatus:
        settings = self.settings
        known_hosts = f"[{settings.host}]:{settings.port} {settings.server_host_key}\n".encode()
        try:
            async with asyncio.timeout(10):
                key = await asyncio.to_thread(asyncssh.read_private_key, settings.private_key_file)
                async with asyncssh.connect(
                    settings.host,
                    port=settings.port,
                    username=settings.username,
                    known_hosts=known_hosts,
                    client_keys=[key],
                    agent_path=None,
                    config=None,
                    password_auth=False,
                    kbdint_auth=False,
                    preferred_auth=["publickey"],
                    connect_timeout=5,
                    login_timeout=5,
                ) as connection:
                    async with connection.create_process(
                        STATUS_COMMAND,
                        encoding=None,
                        stdin=asyncssh.DEVNULL,
                        request_pty=False,
                    ) as process:
                        tasks = [
                            asyncio.create_task(_read_bounded(process.stdout, 8192)),
                            asyncio.create_task(_read_bounded(process.stderr, 2048)),
                        ]
                        try:
                            stdout, _ = await asyncio.gather(*tasks)
                            await process.wait_closed()
                        finally:
                            for task in tasks:
                                task.cancel()
                            await asyncio.gather(*tasks, return_exceptions=True)
                        if process.exit_status != 0:
                            raise StationError("status_command_failed")
                        return parse_status(stdout)
        except asyncssh.HostKeyNotVerifiable:
            raise HostKeyError("host_key_mismatch") from None
        except (asyncssh.PermissionDenied, asyncssh.KeyImportError):
            raise AuthenticationError("authentication_failed") from None
        except (FileNotFoundError, PermissionError):
            raise AuthenticationError("private_key_unavailable") from None
        except (OSError, asyncssh.Error, TimeoutError):
            raise StationError("cannot_connect") from None
