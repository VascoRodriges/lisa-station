"""Actual loopback SSH: pinned key, fixed command and bounded untrusted data."""

import asyncio
import json
from dataclasses import replace

import asyncssh
import pytest

from custom_components.lisa_station.client import (
    ConnectionSettings,
    HostKeyError,
    InvalidConfiguration,
    StationClient,
)
from custom_components.lisa_station.const import STATUS_COMMAND
from custom_components.lisa_station.protocol import ProtocolError


@pytest.mark.parametrize(
    "changes",
    [
        {"host": "host\n*"},
        {"host": "*"},
        {"username": "root;id"},
        {"port": 0},
        {"port": True},
        {"private_key_file": "relative"},
        {"server_host_key": "not-a-key"},
    ],
)
def test_invalid_settings_rejected(settings, changes):
    with pytest.raises(InvalidConfiguration):
        StationClient(replace(settings, **changes))


class KeyOnlyServer(asyncssh.SSHServer):
    def __init__(self, public_key):
        self.public_key = public_key

    def begin_auth(self, username):
        return True

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        return key == self.public_key


@pytest.mark.usefixtures("socket_enabled")
@pytest.mark.parametrize("oversized", [False, True])
async def test_pinning_command_and_limits(tmp_path, status_payload, oversized):
    server_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    key_file = tmp_path / "test_key"
    client_key.write_private_key(key_file)
    commands = []

    async def handle(process):
        commands.append(process.command)
        process.stdout.write(b"x" * 9000 if oversized else json.dumps(status_payload).encode())
        process.exit(0)

    async with asyncssh.create_server(
        lambda: KeyOnlyServer(client_key.convert_to_public()),
        "127.0.0.1",
        0,
        server_host_keys=[server_key],
        process_factory=handle,
        encoding=None,
    ) as server:
        settings = ConnectionSettings(
            "127.0.0.1",
            server.get_port(),
            "root",
            str(key_file),
            server_key.export_public_key().decode().strip(),
        )
        client = StationClient(settings)
        if oversized:
            with pytest.raises(ProtocolError, match="too_large"):
                await client.read_status()
        else:
            assert (await client.read_status()).stock_workers == 4
        assert commands == [STATUS_COMMAND]
        wrong_key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
        with pytest.raises(HostKeyError):
            await StationClient(replace(settings, server_host_key=wrong_key)).read_status()
        assert commands == [STATUS_COMMAND]  # Rejected before any remote command.
    await asyncio.sleep(0)
