"""Read-only device polling."""

import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .client import AuthenticationError, StationClient, StationError
from .const import DOMAIN, SCAN_INTERVAL_SECONDS
from .protocol import FoundationStatus, ProtocolError

_LOGGER = logging.getLogger(__name__)


class StationCoordinator(DataUpdateCoordinator[FoundationStatus]):
    """Offline devices become unavailable; stale data never proves privacy."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, client: StationClient):
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=timedelta(seconds=SCAN_INTERVAL_SECONDS),
            always_update=False,
        )
        self.client = client
        self.entry = entry

    async def _async_update_data(self) -> FoundationStatus:
        try:
            return await self.client.read_status()
        except AuthenticationError:
            raise ConfigEntryAuthFailed("SSH authentication failed") from None
        except ProtocolError:
            raise UpdateFailed("Unsupported station status") from None
        except StationError:
            raise UpdateFailed("Station unavailable or host key changed") from None
