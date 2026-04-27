"""Config flow for Nokia FastMile gateways."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import NokiaFastMileClient, NokiaFastMileError, async_validate_credentials
from .const import CONF_USE_SSL, DEFAULT_HOST, DEFAULT_PORT, DEFAULT_USERNAME, DOMAIN


STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST, default=DEFAULT_HOST): str,
        vol.Required(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Required(CONF_USERNAME, default=DEFAULT_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Required(CONF_USE_SSL, default=False): bool,
    }
)


async def _validate_input(
    hass: HomeAssistant,
    data: dict[str, Any],
) -> dict[str, str]:
    """Validate the user input allows us to connect."""
    client = NokiaFastMileClient(
        session=async_get_clientsession(hass),
        host=data[CONF_HOST],
        port=data[CONF_PORT],
        username=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
        use_ssl=data[CONF_USE_SSL],
    )
    device_status = await async_validate_credentials(client)
    serial_number = str(device_status.get("SerialNumber") or data[CONF_HOST])
    title = str(device_status.get("ModelName") or "Nokia FastMile")
    return {"serial_number": serial_number, "title": title}


class NokiaConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Nokia FastMile."""

    VERSION = 1

    async def async_step_user(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                info = await _validate_input(self.hass, user_input)
            except ConfigEntryAuthFailed:
                errors["base"] = "invalid_auth"
            except NokiaFastMileError:
                errors["base"] = "cannot_connect"
            else:
                await self.async_set_unique_id(info["serial_number"])
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=info["title"], data=user_input)

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )
