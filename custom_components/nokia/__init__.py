"""Home Assistant integration for Nokia FastMile gateways."""

from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .api import NokiaFastMileAuthError, NokiaFastMileClient
from .const import CONF_USE_SSL, DEFAULT_SCAN_INTERVAL, DOMAIN

PLATFORMS: list[Platform] = [Platform.SENSOR]
LOGGER = logging.getLogger(__name__)

type NokiaConfigEntry = ConfigEntry[NokiaDataUpdateCoordinator]


async def async_setup_entry(hass: HomeAssistant, entry: NokiaConfigEntry) -> bool:
    """Set up Nokia FastMile from a config entry."""
    client = NokiaFastMileClient(
        session=async_get_clientsession(hass),
        host=entry.data[CONF_HOST],
        port=entry.data[CONF_PORT],
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        use_ssl=entry.data[CONF_USE_SSL],
    )
    coordinator = NokiaDataUpdateCoordinator(hass, client, entry)

    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: NokiaConfigEntry) -> bool:
    """Unload a Nokia FastMile config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


class NokiaDataUpdateCoordinator(DataUpdateCoordinator[dict[str, object]]):
    """Coordinator for Nokia FastMile gateway data."""

    config_entry: NokiaConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        client: NokiaFastMileClient,
        entry: NokiaConfigEntry,
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            logger=LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
            config_entry=entry,
        )
        self.client = client

    async def _async_update_data(self) -> dict[str, object]:
        """Fetch fresh gateway data."""
        try:
            data = await self.client.async_get_data()
        except NokiaFastMileAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err

        if self.data:
            for key in ("web_device_status", "statistics_status"):
                if not data.get(key) and self.data.get(key):
                    data[key] = self.data[key]

        return data
