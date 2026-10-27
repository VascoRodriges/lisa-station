"""Physical mute, root filesystem, and deliberately unknown isolation."""

from homeassistant.components.binary_sensor import BinarySensorEntity

from .entity import StationEntity

KEYS = ("physical_mute", "root_readonly", "isolation_confirmed")


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities(StationBinarySensor(entry.runtime_data, key) for key in KEYS)


class StationBinarySensor(StationEntity, BinarySensorEntity):
    @property
    def is_on(self):
        return getattr(self.coordinator.data, self._attr_translation_key)
