"""Technical facts only; omit connection data, identifiers and speech."""

from dataclasses import asdict


async def async_get_config_entry_diagnostics(hass, entry):
    coordinator = entry.runtime_data
    return {
        "integration_version": "0.1.0",
        "controller_kind": "controller_foundation",
        "last_update_success": coordinator.last_update_success,
        "status": asdict(coordinator.data) if coordinator.last_update_success else None,
        "isolation_confirmed": None,
        "mode_changes_supported": False,
    }
