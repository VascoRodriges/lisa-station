"""Read-only facts; no inferred Alice/Lisa or privacy success state."""

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity

from .entity import StationEntity

KEYS = ("controller_state", "stock_workers", "stock_launchers", "stopped_launchers")


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities(StationSensor(entry.runtime_data, key) for key in KEYS)


class StationSensor(StationEntity, SensorEntity):
    def __init__(self, coordinator, key):
        super().__init__(coordinator, key)
        if key == "controller_state":
            self._attr_device_class = SensorDeviceClass.ENUM
            self._attr_options = ["unmanaged"]

    @property
    def native_value(self):
        if self._attr_translation_key == "controller_state":
            return "unmanaged"
        return getattr(self.coordinator.data, self._attr_translation_key)
