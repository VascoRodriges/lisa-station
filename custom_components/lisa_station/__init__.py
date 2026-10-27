"""Lisa Station: local device integration, diagnostic preview."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PORT, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant

from .client import ConnectionSettings, StationClient
from .const import CONF_PRIVATE_KEY_FILE, CONF_SERVER_HOST_KEY
from .coordinator import StationCoordinator

PLATFORMS = (Platform.SENSOR, Platform.BINARY_SENSOR)
type LisaStationConfigEntry = ConfigEntry[StationCoordinator]


def settings_from_data(data) -> ConnectionSettings:
    return ConnectionSettings(
        host=data[CONF_HOST],
        port=data[CONF_PORT],
        username=data[CONF_USERNAME],
        private_key_file=data[CONF_PRIVATE_KEY_FILE],
        server_host_key=data[CONF_SERVER_HOST_KEY],
    )


async def async_setup_entry(hass: HomeAssistant, entry: LisaStationConfigEntry) -> bool:
    coordinator = StationCoordinator(hass, entry, StationClient(settings_from_data(entry.data)))
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: LisaStationConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
