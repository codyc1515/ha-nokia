"""Sensors for Nokia FastMile gateways."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfInformation
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import NokiaDataUpdateCoordinator
from .const import DOMAIN, MANUFACTURER


def _first_item(data: dict[str, Any], group: str) -> dict[str, Any]:
    """Return the first dict in a cell status group."""
    cell_status = data.get("cell_status")
    if not isinstance(cell_status, dict):
        return {}
    value = cell_status.get(group)
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    return {}


def _first_statistics_item(data: dict[str, Any], group: str) -> dict[str, Any]:
    """Return the first dict in a statistics status group."""
    statistics_status = data.get("statistics_status")
    if not isinstance(statistics_status, dict):
        return {}
    value = statistics_status.get(group)
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    return {}


def _device_status(data: dict[str, Any]) -> dict[str, Any]:
    """Return device status data."""
    device_status = data.get("device_status")
    return device_status if isinstance(device_status, dict) else {}


def _web_device_status(data: dict[str, Any]) -> dict[str, Any]:
    """Return web device status data."""
    web_device_status = data.get("web_device_status")
    return web_device_status if isinstance(web_device_status, dict) else {}


def _generic(data: dict[str, Any], key: str) -> Any:
    """Return a generic cellular value."""
    return _first_item(data, "cell_stat_generic").get(key)


def _lte(data: dict[str, Any], key: str) -> Any:
    """Return an LTE cellular value."""
    return _first_item(data, "cell_stat_lte").get(key)


def _nr(data: dict[str, Any], key: str) -> Any:
    """Return a 5G cellular value."""
    return _first_item(data, "cell_stat_5G").get(key)


def _network_cfg(data: dict[str, Any], key: str) -> Any:
    """Return a network configuration value."""
    return _first_statistics_item(data, "network_cfg").get(key)


def _sim_cfg(data: dict[str, Any], key: str) -> Any:
    """Return a SIM configuration value."""
    return _first_statistics_item(data, "sim_cfg").get(key)


def _web_device(data: dict[str, Any], key: str) -> Any:
    """Return a web device status value."""
    return _web_device_status(data).get(key)


def _web_nested_device(data: dict[str, Any], group: str, key: str) -> Any:
    """Return a nested web device status value."""
    value = _web_device_status(data).get(group)
    if isinstance(value, dict):
        return value.get(key)
    return None


def _bool_text(value: Any) -> str | None:
    """Return a lower-case true/false string for boolean gateway values."""
    if value is None or value == "":
        return None
    return "true" if bool(value) else "false"


@dataclass(frozen=True, kw_only=True)
class NokiaSensorEntityDescription(SensorEntityDescription):
    """Description for a Nokia FastMile sensor."""

    value_fn: Callable[[dict[str, Any]], Any]


GENERIC_SENSORS: tuple[NokiaSensorEntityDescription, ...] = (
    NokiaSensorEntityDescription(
        key="roaming",
        translation_key="roaming",
        value_fn=lambda data: _generic(data, "RoamingStatus"),
    ),
    NokiaSensorEntityDescription(
        key="technology",
        translation_key="technology",
        value_fn=lambda data: _generic(data, "CurrentAccessTechnology"),
    ),
    NokiaSensorEntityDescription(
        key="tac",
        translation_key="tac",
        value_fn=lambda data: _generic(data, "X_ALU_COM_TAC"),
    ),
    NokiaSensorEntityDescription(
        key="bytes_sent",
        translation_key="bytes_sent",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.BYTES,
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda data: _generic(data, "BytesSent"),
    ),
    NokiaSensorEntityDescription(
        key="bytes_received",
        translation_key="bytes_received",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.BYTES,
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda data: _generic(data, "BytesReceived"),
    ),
)


STATISTICS_SENSORS: tuple[NokiaSensorEntityDescription, ...] = (
    NokiaSensorEntityDescription(
        key="imei",
        translation_key="imei",
        value_fn=lambda data: _network_cfg(data, "IMEI"),
    ),
    NokiaSensorEntityDescription(
        key="sim_type",
        translation_key="sim_type",
        value_fn=lambda data: _sim_cfg(data, "Type"),
    ),
    NokiaSensorEntityDescription(
        key="sim_status",
        translation_key="sim_status",
        value_fn=lambda data: _sim_cfg(data, "Status"),
    ),
    NokiaSensorEntityDescription(
        key="imsi",
        translation_key="imsi",
        value_fn=lambda data: _sim_cfg(data, "IMSI"),
    ),
    NokiaSensorEntityDescription(
        key="iccid",
        translation_key="iccid",
        value_fn=lambda data: _sim_cfg(data, "ICCID"),
    ),
    NokiaSensorEntityDescription(
        key="msisdn",
        translation_key="msisdn",
        value_fn=lambda data: _sim_cfg(data, "MSISDN"),
    ),
)


WEB_DEVICE_SENSORS: tuple[NokiaSensorEntityDescription, ...] = (
    NokiaSensorEntityDescription(
        key="friendly_name",
        translation_key="friendly_name",
        value_fn=lambda data: _web_device(data, "X_ASB_COM_FriendlyName"),
    ),
    NokiaSensorEntityDescription(
        key="root_mac_address",
        translation_key="root_mac_address",
        value_fn=lambda data: _web_device(data, "RootMacAddress"),
    ),
    NokiaSensorEntityDescription(
        key="ip_address",
        translation_key="ip_address",
        value_fn=lambda data: _web_device(data, "IPAddress"),
    ),
    NokiaSensorEntityDescription(
        key="lot_number",
        translation_key="lot_number",
        value_fn=lambda data: _web_device(data, "lot_number"),
    ),
    NokiaSensorEntityDescription(
        key="cpu_usage",
        translation_key="cpu_usage",
        native_unit_of_measurement="%",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: _web_nested_device(data, "cpu_usageinfo", "CPUUsage"),
    ),
    NokiaSensorEntityDescription(
        key="memory_total",
        translation_key="memory_total",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement="KiB",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: _web_nested_device(data, "mem_info", "Total"),
    ),
    NokiaSensorEntityDescription(
        key="memory_free",
        translation_key="memory_free",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement="KiB",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: _web_nested_device(data, "mem_info", "Free"),
    ),
)


RADIO_SENSORS: tuple[NokiaSensorEntityDescription, ...] = (
    NokiaSensorEntityDescription(
        key="enb",
        translation_key="enb",
        value_fn=lambda data: _lte(data, "eNBID"),
    ),
    NokiaSensorEntityDescription(
        key="cell",
        translation_key="cell",
        value_fn=lambda data: _lte(data, "Cellid"),
    ),
    NokiaSensorEntityDescription(
        key="snr",
        translation_key="snr",
        native_unit_of_measurement="dB",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: _lte(data, "SNRCurrent"),
    ),
    NokiaSensorEntityDescription(
        key="rsrp",
        translation_key="rsrp",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        native_unit_of_measurement="dBm",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: _lte(data, "RSRPCurrent"),
    ),
    NokiaSensorEntityDescription(
        key="rsrq",
        translation_key="rsrq",
        native_unit_of_measurement="dB",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: _lte(data, "RSRQCurrent"),
    ),
    NokiaSensorEntityDescription(
        key="rssi",
        translation_key="rssi",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        native_unit_of_measurement="dBm",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: _lte(data, "RSSICurrent"),
    ),
    NokiaSensorEntityDescription(
        key="band",
        translation_key="band",
        value_fn=lambda data: _lte(data, "Band"),
    ),
    NokiaSensorEntityDescription(
        key="bandwidth",
        translation_key="bandwidth",
        value_fn=lambda data: _lte(data, "Bandwidth"),
    ),
    NokiaSensorEntityDescription(
        key="pci",
        translation_key="pci",
        value_fn=lambda data: _lte(data, "AttachedCellPci"),
    ),
    NokiaSensorEntityDescription(
        key="earfcn",
        translation_key="earfcn",
        value_fn=lambda data: _lte(data, "AttachedCellEArfcn"),
    ),
    NokiaSensorEntityDescription(
        key="carrier",
        translation_key="carrier",
        value_fn=lambda data: _lte(data, "PLMNName"),
    ),
    NokiaSensorEntityDescription(
        key="power",
        translation_key="power",
        native_unit_of_measurement="dBm",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: _lte(data, "TxPower"),
    ),
    NokiaSensorEntityDescription(
        key="cqi",
        translation_key="cqi",
        value_fn=lambda data: _lte(data, "Cw0CQI"),
    ),
    NokiaSensorEntityDescription(
        key="nsa",
        translation_key="nsa",
        value_fn=lambda data: _bool_text(_lte(data, "NRCellAssociated")),
    ),
)


NR_OVERRIDES: dict[str, Callable[[dict[str, Any]], Any]] = {
    "cell": lambda data: _nr(data, "AttachedCellNci"),
    "snr": lambda data: _nr(data, "SNRCurrent"),
    "rsrp": lambda data: _nr(data, "RSRPCurrent"),
    "rsrq": lambda data: _nr(data, "RSRQCurrent"),
    "band": lambda data: _nr(data, "Band"),
    "bandwidth": lambda data: _nr(data, "Bandwidth"),
    "pci": lambda data: _nr(data, "AttachedCellPci"),
    "earfcn": lambda data: _nr(data, "AttachedCellNRArfcn"),
    "carrier": lambda data: _nr(data, "PLMNName"),
    "cqi": lambda data: _nr(data, "Cw0CQI"),
}

NR_UNSUPPORTED_KEYS = {"enb", "rssi", "power", "nsa"}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Nokia FastMile sensors."""
    coordinator: NokiaDataUpdateCoordinator = entry.runtime_data

    entities: list[NokiaSensor] = [
        NokiaSensor(coordinator, description, None)
        for description in GENERIC_SENSORS
    ]

    entities.extend(
        NokiaSensor(coordinator, description, None)
        for description in STATISTICS_SENSORS
    )

    entities.extend(
        NokiaSensor(coordinator, description, None)
        for description in WEB_DEVICE_SENSORS
    )

    entities.extend(
        NokiaSensor(coordinator, description, "4G")
        for description in RADIO_SENSORS
    )

    entities.extend(
        NokiaSensor(
            coordinator,
            NokiaSensorEntityDescription(
                key=description.key,
                translation_key=description.translation_key,
                device_class=description.device_class,
                native_unit_of_measurement=description.native_unit_of_measurement,
                state_class=description.state_class,
                value_fn=NR_OVERRIDES[description.key],
            ),
            "5G",
        )
        for description in RADIO_SENSORS
        if description.key not in NR_UNSUPPORTED_KEYS
    )

    async_add_entities(entities)


class NokiaSensor(CoordinatorEntity[NokiaDataUpdateCoordinator], SensorEntity):
    """Nokia FastMile diagnostic sensor."""

    entity_description: NokiaSensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: NokiaDataUpdateCoordinator,
        description: NokiaSensorEntityDescription,
        prefix: str | None,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._prefix = prefix
        key = f"{prefix.lower()}_{description.key}" if prefix else description.key
        self._attr_unique_id = f"{self._serial_number}_{key}"
        name = description.translation_key or description.key
        self._attr_translation_key = (
            name if prefix is None else f"{prefix.lower()}_{name}"
        )
        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_device_info = self._device_info

    @property
    def native_value(self) -> Any:
        """Return the sensor state."""
        value = self.entity_description.value_fn(self.coordinator.data)
        if value == "":
            return None
        return value

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
        return DeviceInfo(
            identifiers={(DOMAIN, self._serial_number)},
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
