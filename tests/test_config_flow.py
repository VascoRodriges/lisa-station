"""Setup, errors, duplicate protection and connection reconfiguration."""

from unittest.mock import patch

import pytest
from homeassistant.config_entries import SOURCE_USER
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.lisa_station.client import AuthenticationError, HostKeyError, StationError
from custom_components.lisa_station.const import DOMAIN
from custom_components.lisa_station.protocol import ProtocolError


async def test_setup_and_duplicate(hass, connection_data, settings, mock_status):
    with patch("custom_components.lisa_station.async_setup_entry", return_value=True):
        flow = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
        assert flow["type"] == FlowResultType.FORM
        result = await hass.config_entries.flow.async_configure(flow["flow_id"], connection_data)
        assert result["type"] == FlowResultType.CREATE_ENTRY
        assert result["result"].unique_id == settings.unique_id
        await hass.async_block_till_done()
        duplicate = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_USER}, data=connection_data
        )
        assert duplicate["type"] == FlowResultType.ABORT
        assert duplicate["reason"] == "already_configured"


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (AuthenticationError(), "invalid_auth"),
        (HostKeyError(), "host_key_mismatch"),
        (StationError(), "cannot_connect"),
        (ProtocolError(), "unsupported_agent"),
    ],
)
async def test_failure_creates_no_entry(hass, connection_data, mock_status, error, reason):
    mock_status.side_effect = error
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}, data=connection_data
    )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {"base": reason}
    assert not hass.config_entries.async_entries(DOMAIN)


async def test_reconfigure_preserves_device_identity(hass, connection_data, settings, mock_status):
    entry = MockConfigEntry(domain=DOMAIN, data=connection_data, unique_id=settings.unique_id)
    entry.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "reconfigure", "entry_id": entry.entry_id}
    )
    changed = connection_data | {"host": "new-address.example.invalid"}
    with patch("homeassistant.config_entries.ConfigEntries.async_reload", return_value=True):
        result = await hass.config_entries.flow.async_configure(result["flow_id"], changed)
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert entry.data["host"] == changed["host"]
    assert entry.unique_id == settings.unique_id
