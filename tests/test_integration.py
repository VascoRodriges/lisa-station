"""Real HA entity registration, safe unknown state, offline and unload."""

from dataclasses import replace

from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.lisa_station.client import StationError
from custom_components.lisa_station.const import DOMAIN
from custom_components.lisa_station.diagnostics import async_get_config_entry_diagnostics


async def test_entities_availability_and_unload(hass, connection_data, settings, mock_status, device_status):
    entry = MockConfigEntry(
        domain=DOMAIN, title="Test station", data=connection_data, unique_id=settings.unique_id
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    registry = er.async_get(hass)

    def state(key, domain="binary_sensor"):
        entity_id = registry.async_get_entity_id(domain, DOMAIN, f"{settings.unique_id}_{key}")
        return hass.states.get(entity_id).state

    assert state("physical_mute") == "off"
    assert state("root_readonly") == "on"
    assert state("isolation_confirmed") == "unknown"
    assert state("stock_workers", "sensor") == "4"
    mock_status.return_value = replace(device_status, physical_mute=True)
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    assert state("physical_mute") == "on"
    diagnostics = await async_get_config_entry_diagnostics(hass, entry)
    serialized = str(diagnostics)
    for value in (
        connection_data["host"],
        connection_data["private_key_file"],
        connection_data["server_host_key"],
    ):
        assert value not in serialized
    assert diagnostics["isolation_confirmed"] is None
    mock_status.side_effect = StationError()
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    assert state("physical_mute") == "unavailable"
    assert state("isolation_confirmed") == "unavailable"
    assert await hass.config_entries.async_unload(entry.entry_id)
