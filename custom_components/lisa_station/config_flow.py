"""UI setup and explicit connection reconfiguration, with pinned server key."""

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_HOST, CONF_PORT, CONF_USERNAME
from homeassistant.core import callback
from homeassistant.helpers import selector

from . import settings_from_data
from .client import AuthenticationError, HostKeyError, InvalidConfiguration, StationClient, StationError
from .const import (
    CONF_PRIVATE_KEY_FILE,
    CONF_SERVER_HOST_KEY,
    DEFAULT_KEY_FILE,
    DEFAULT_PORT,
    DEFAULT_USERNAME,
    DOMAIN,
)
from .protocol import ProtocolError


@callback
def connection_schema(defaults=None):
    defaults = defaults or {}
    return vol.Schema(
        {
            vol.Required(CONF_HOST, default=defaults.get(CONF_HOST, "")): str,
            vol.Required(CONF_PORT, default=defaults.get(CONF_PORT, DEFAULT_PORT)): vol.All(
                vol.Coerce(int), vol.Range(min=1, max=65535)
            ),
            vol.Required(CONF_USERNAME, default=defaults.get(CONF_USERNAME, DEFAULT_USERNAME)): str,
            vol.Required(
                CONF_PRIVATE_KEY_FILE, default=defaults.get(CONF_PRIVATE_KEY_FILE, DEFAULT_KEY_FILE)
            ): str,
            vol.Required(
                CONF_SERVER_HOST_KEY, default=defaults.get(CONF_SERVER_HOST_KEY, "")
            ): selector.TextSelector(),
        }
    )


class LisaStationFlow(ConfigFlow, domain=DOMAIN):
    """Only a verified, supported diagnostic response creates a device."""

    VERSION = 1

    async def async_step_user(self, user_input=None) -> ConfigFlowResult:
        return await self._connection_step("user", user_input)

    async def async_step_reconfigure(self, user_input=None) -> ConfigFlowResult:
        return await self._connection_step("reconfigure", user_input)

    async def async_step_reauth(self, entry_data) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None) -> ConfigFlowResult:
        return await self._connection_step("reauth_confirm", user_input)

    async def _connection_step(self, step_id, user_input):
        errors = {}
        existing = None
        if step_id == "reconfigure":
            existing = self._get_reconfigure_entry()
        elif step_id == "reauth_confirm":
            existing = self._get_reauth_entry()
        defaults = user_input or (existing.data if existing else {})
        if user_input is not None:
            try:
                client = StationClient(settings_from_data(user_input))
                await client.read_status()
            except HostKeyError:
                errors["base"] = "host_key_mismatch"
            except AuthenticationError:
                errors["base"] = "invalid_auth"
            except InvalidConfiguration:
                errors["base"] = "invalid_settings"
            except ProtocolError:
                errors["base"] = "unsupported_agent"
            except StationError:
                errors["base"] = "cannot_connect"
            else:
                await self.async_set_unique_id(client.settings.unique_id)
                if existing:
                    if existing.unique_id != client.settings.unique_id:
                        return self.async_abort(reason="wrong_device")
                    return self.async_update_reload_and_abort(existing, data_updates=user_input)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title="Lisa Station", data=user_input)
        return self.async_show_form(step_id=step_id, data_schema=connection_schema(defaults), errors=errors)
