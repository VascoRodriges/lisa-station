"""Synthetic fixtures only: no household addresses, keys or voice data."""

import json
from unittest.mock import AsyncMock, patch

import asyncssh
import pytest

from custom_components.lisa_station.client import ConnectionSettings
from custom_components.lisa_station.protocol import parse_status


@pytest.fixture(autouse=True)
def custom_integrations(enable_custom_integrations):
    yield


@pytest.fixture
def status_payload():
    return dict(
        schema_version=1,
        agent_kind="controller_foundation",
        device_model="yandex,station-midi",
        managed=False,
        actual_mode="unmanaged",
        requested_mode=None,
        isolation="unverified",
        apply_supported=False,
        stock_workers=4,
        stock_launchers=1,
        stopped_launchers=0,
        physical_mute=False,
        root_readonly=True,
        capabilities=["status", "sandbox-selftest"],
        audio_opened=False,
    )


@pytest.fixture
def device_status(status_payload):
    return parse_status(json.dumps(status_payload))


@pytest.fixture
def connection_data(tmp_path):
    server_key = asyncssh.generate_private_key("ssh-ed25519")
    return dict(
        host="station.example.invalid",
        port=2222,
        username="root",
        private_key_file=str(tmp_path / "dedicated_key"),
        server_host_key=server_key.export_public_key().decode().strip(),
    )


@pytest.fixture
def settings(connection_data):
    return ConnectionSettings(**connection_data)


@pytest.fixture
def mock_status(device_status):
    with patch(
        "custom_components.lisa_station.client.StationClient.read_status",
        new=AsyncMock(return_value=device_status),
    ) as mock:
        yield mock
