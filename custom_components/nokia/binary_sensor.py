"""Binary sensors for Nokia FastMile gateways."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC, DeviceInfo
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import NokiaDataUpdateCoordinator
from .const import DOMAIN, MANUFACTURER
from .sensor import _device_status, _lte, _web_device_status


@dataclass(frozen=True, kw_only=True)
class NokiaBinarySensorEntityDescription(BinarySensorEntityDescription):
    """Description for a Nokia FastMile binary sensor."""

    value_fn: Callable[[dict[str, Any]], Any]


BINARY_SENSORS: tuple[NokiaBinarySensorEntityDescription, ...] = (
    NokiaBinarySensorEntityDescription(
        key="nsa",
        translation_key="5g_nsa",
        value_fn=lambda data: _lte(data, "NRCellAssociated"),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Nokia FastMile binary sensors."""
    coordinator: NokiaDataUpdateCoordinator = entry.runtime_data
    async_add_entities(
        NokiaBinarySensor(coordinator, description) for description in BINARY_SENSORS
    )


class NokiaBinarySensor(
    CoordinatorEntity[NokiaDataUpdateCoordinator], BinarySensorEntity
):
    """Nokia FastMile diagnostic binary sensor."""

    entity_description: NokiaBinarySensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: NokiaDataUpdateCoordinator,
        description: NokiaBinarySensorEntityDescription,
    ) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{self._serial_number}_5g_{description.key}"
        self._attr_translation_key = description.translation_key or description.key
        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_device_info = self._device_info

    @property
    def is_on(self) -> bool | None:
        """Return true if NR NSA is active."""
        value = self.entity_description.value_fn(self.coordinator.data)
        if value in (None, ""):
            return None
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"1", "true", "yes", "on"}:
                return True
            if lowered in {"0", "false", "no", "off"}:
                return False
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        return None

    @property
    def _serial_number(self) -> str:
        """Return the gateway serial number."""
        return str(
            _device_status(self.coordinator.data).get("SerialNumber")
            or self.coordinator.config_entry.entry_id
        )

    @property
    def _device_info(self) -> DeviceInfo:
        """Return device registry information."""
        device_status = _device_status(self.coordinator.data)
        web_device_status = _web_device_status(self.coordinator.data)
        root_mac_address = str(web_device_status.get("RootMacAddress") or "").strip()
        connections = (
            {(CONNECTION_NETWORK_MAC, root_mac_address)}
            if root_mac_address
            else None
        )
        return DeviceInfo(
            identifiers={(DOMAIN, self._serial_number)},
            connections=connections,
            manufacturer=MANUFACTURER,
            model=str(
                web_device_status.get("ModelName")
                or device_status.get("ModelName")
                or ""
            ),
            serial_number=self._serial_number,
            sw_version=str(
                web_device_status.get("SoftwareVersion")
                or device_status.get("SoftwareVersion")
                or ""
            ),
            hw_version=str(
                web_device_status.get("HardwareVersion")
                or device_status.get("HardwareVersion")
                or ""
            ),
        )
