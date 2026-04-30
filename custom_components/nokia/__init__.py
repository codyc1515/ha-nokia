"""Home Assistant integration for Nokia FastMile gateways."""

from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .api import NokiaFastMileAuthError, NokiaFastMileClient
from .const import (
    CONF_UNIFI_EMULATION_ENABLED,
    CONF_USE_SSL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_UNIFI_INFORM_INTERVAL,
    DOMAIN,
)
from .unifi import UniFiInformEmulator, UniFiInformError

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.BINARY_SENSOR]
LOGGER = logging.getLogger(__name__)
UNIFI_STORAGE_VERSION = 1

type NokiaConfigEntry = ConfigEntry[NokiaDataUpdateCoordinator]


async def async_setup_entry(hass: HomeAssistant, entry: NokiaConfigEntry) -> bool:
    """Set up Nokia FastMile from a config entry."""
    config = {**entry.data, **entry.options}
    session = async_get_clientsession(hass)
    client = NokiaFastMileClient(
        session=session,
        host=config[CONF_HOST],
        port=config[CONF_PORT],
        username=config[CONF_USERNAME],
        password=config[CONF_PASSWORD],
        use_ssl=config[CONF_USE_SSL],
    )
    unifi: UniFiInformEmulator | None = None
    unifi_store: Store[dict[str, object]] | None = None
    if config.get(CONF_UNIFI_EMULATION_ENABLED, False):
        unifi_store = Store(
            hass,
            UNIFI_STORAGE_VERSION,
            f"{DOMAIN}_unifi_{entry.entry_id}",
        )
        unifi_state = await unifi_store.async_load() or {}
        unifi = UniFiInformEmulator(session, {**config, **unifi_state})
    coordinator = NokiaDataUpdateCoordinator(hass, client, entry, unifi, unifi_store)

    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = coordinator
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_update_listener(hass: HomeAssistant, entry: NokiaConfigEntry) -> None:
    """Reload entry when options change."""
    await hass.config_entries.async_reload(entry.entry_id)


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
        unifi: UniFiInformEmulator | None,
        unifi_store: Store[dict[str, object]] | None,
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            logger=LOGGER,
            name=DOMAIN,
            update_interval=timedelta(
                seconds=DEFAULT_UNIFI_INFORM_INTERVAL if unifi else DEFAULT_SCAN_INTERVAL
            ),
            config_entry=entry,
        )
        self.client = client
        self.unifi = unifi
        self.unifi_store = unifi_store

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

        if self.unifi:
            try:
                result = await self.unifi.async_send(data)
            except UniFiInformError as err:
                LOGGER.warning("UniFi emulation update failed: %s", err)
            else:
                if result.interval:
                    self.update_interval = timedelta(seconds=result.interval)
                if result.changed and result.storage and self.unifi_store:
                    await self.unifi_store.async_save(result.storage)

        return data
