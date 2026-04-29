"""UniFi U5G Max inform emulation for Nokia FastMile data."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import logging
import os
import re
import struct
import time
import zlib
from typing import Any
import urllib.parse

from aiohttp import ClientError, ClientSession

from .const import (
    CONF_UNIFI_AES_GCM,
    CONF_UNIFI_AUTHKEY,
    CONF_UNIFI_CFGVERSION,
    CONF_UNIFI_GEO_INFO,
    CONF_UNIFI_GEO_IP,
    CONF_UNIFI_INFORM_HOST,
    CONF_UNIFI_INFORM_PORT,
    CONF_UNIFI_INFORM_URL,
    CONF_UNIFI_MGMT_URL,
    DEFAULT_UNIFI_INFORM_HOST,
    DEFAULT_UNIFI_INFORM_INTERVAL,
    DEFAULT_UNIFI_INFORM_PORT,
)

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover - optional sidecar dependency
    AES = None


LOGGER = logging.getLogger(__name__)

MAGIC = b"TNBU"
PACKET_VERSION = 1
PAYLOAD_VERSION_JSON = 1
FLAG_ENCRYPTED = 0x01
FLAG_ZLIB = 0x02
FLAG_SNAPPY = 0x04
FLAG_GCM = 0x08
DEFAULT_AUTHKEY = hashlib.md5(b"ubnt").hexdigest()

MODEL = "UMBBE630"
MODEL_DISPLAY = "U5G Max"
DEVICE_TYPE = "ugw"
PLATFORM = "e630"
DISPLAYABLE_VERSION = "99.99.99"
FIRMWARE_BUILD = "18253"
FIRMWARE_VERSION = f"{DISPLAYABLE_VERSION}.{FIRMWARE_BUILD}"
KERNEL_VERSION = "5.15.134"
DEFAULT_NETMASK = "255.255.255.0"
DEFAULT_GATEWAY_IP = "192.168.1.1"
DEFAULT_DNS = "1.1.1.1"
GEO_URL = "https://geo.svc.ui.com/geo"
GEO_KEYS = (
    "address",
    "continent_code",
    "country_code",
    "country_name",
    "city",
    "latitude",
    "longitude",
    "accuracy",
    "asn",
    "organization",
    "timezone",
    "isp",
)
PUBLIC_IP_KEYS = (
    "PublicIPAddress",
    "ExternalIPAddress",
    "ExternalIP",
    "WanIPAddress",
    "WANIPAddress",
    "WANIP",
    "IPv4Address",
    "IPAddress",
    "IPAddr",
    "IpAddress",
    "X_ALU_COM_IPAddress",
    "X_ALU_COM_WANIPAddress",
    "X_ASB_COM_WANIPAddress",
)
CARRIER_KEYS = (
    "PLMNName",
    "NetworkOperator",
    "NetworkOperatorName",
    "OperatorName",
    "ServiceProviderName",
    "SPN",
    "Carrier",
    "CarrierName",
)


@dataclass
class UniFiInformResult:
    """Result of one UniFi inform attempt."""

    changed: bool = False
    interval: float | None = None
    storage: dict[str, Any] | None = None


class UniFiInformError(Exception):
    """UniFi inform sidecar error."""


class UniFiInformEmulator:
    """Send UniFi U5G Max informs using the coordinator's Nokia data."""

    def __init__(self, session: ClientSession, config: dict[str, Any]) -> None:
        """Initialize the emulator."""
        self._session = session
        host = str(config.get(CONF_UNIFI_INFORM_HOST) or DEFAULT_UNIFI_INFORM_HOST)
        port = int(config.get(CONF_UNIFI_INFORM_PORT) or DEFAULT_UNIFI_INFORM_PORT)
        self._default_inform_url = f"http://{host}:{port}/inform"
        saved_url = str(config.get(CONF_UNIFI_INFORM_URL) or "")
        self._inform_url = saved_url if _is_inform_endpoint(saved_url) else self._default_inform_url
        self._mgmt_url = str(config.get(CONF_UNIFI_MGMT_URL) or "")
        self._authkey = str(config.get(CONF_UNIFI_AUTHKEY) or DEFAULT_AUTHKEY)
        self._cfgversion = str(config.get(CONF_UNIFI_CFGVERSION) or "0000000000000000")
        self._aes_gcm = bool(config.get(CONF_UNIFI_AES_GCM, False))
        geo_info = config.get(CONF_UNIFI_GEO_INFO)
        self._geo = _normalise_geo(geo_info) if isinstance(geo_info, dict) else {}
        self._geo_ip = str(config.get(CONF_UNIFI_GEO_IP) or self._geo.get("address") or "")
        self._geo_lookup_key = self._geo_ip
        self._adopted = self._authkey != DEFAULT_AUTHKEY
        self._mac: str | None = None

    async def async_send(self, data: dict[str, Any]) -> UniFiInformResult:
        """Send one inform using already-fetched Nokia data."""
        if AES is None:
            raise UniFiInformError("pycryptodome is required for UniFi emulation")

        mac = self._mac_for_data(data)
        geo_changed = await self._ensure_geo(data)
        payload = self._payload(data, mac)
        packet = _encode_tnbu(payload, mac, self._authkey, self._aes_gcm)
        LOGGER.debug(
            "Sending UniFi inform to %s as %s adopted=%s gcm=%s",
            self._inform_url,
            mac,
            self._adopted,
            self._aes_gcm,
        )

        try:
            async with self._session.post(
                self._inform_url,
                data=packet,
                headers={
                    "content-type": "application/x-binary",
                    "user-agent": "UBNT-NokiaFastMile/0.1",
                },
                timeout=5,
            ) as response:
                body = await response.read()
                status = response.status
        except ClientError as err:
            raise UniFiInformError(f"Could not connect to UniFi controller: {err}") from err

        if status == 404 and not self._adopted:
            LOGGER.debug("UniFi controller has no adopted record for %s yet", mac)
            return UniFiInformResult(
                changed=geo_changed,
                storage=self.storage if geo_changed else None,
            )
        if status == 400 and self._adopted:
            LOGGER.warning("UniFi controller rejected saved auth for %s; resetting adoption state", mac)
            self._reset()
            return UniFiInformResult(changed=True, storage=self.storage)
        if status >= 400:
            LOGGER.warning("UniFi inform returned HTTP %s", status)
            return UniFiInformResult(
                changed=geo_changed,
                storage=self.storage if geo_changed else None,
            )
        if not body:
            return UniFiInformResult(
                changed=geo_changed,
                storage=self.storage if geo_changed else None,
            )

        decoded, meta = _decode_tnbu(body, [self._authkey, DEFAULT_AUTHKEY])
        LOGGER.debug("Decoded UniFi response meta=%s payload=%s", meta, decoded)
        result = self._handle_response(decoded)
        if geo_changed:
            result.changed = True
            result.storage = self.storage
        return result

    @property
    def storage(self) -> dict[str, Any]:
        """Return persistent UniFi adoption state."""
        return {
            CONF_UNIFI_AES_GCM: self._aes_gcm,
            CONF_UNIFI_AUTHKEY: self._authkey,
            CONF_UNIFI_CFGVERSION: self._cfgversion,
            CONF_UNIFI_INFORM_URL: self._inform_url,
            CONF_UNIFI_MGMT_URL: self._mgmt_url,
            CONF_UNIFI_GEO_INFO: self._geo,
            CONF_UNIFI_GEO_IP: self._geo_ip,
        }

    def _handle_response(self, decoded: dict[str, Any]) -> UniFiInformResult:
        response_type = decoded.get("_type") or decoded.get("cmd")
        changed = False
        interval: float | None = None

        if response_type == "setdefault":
            self._reset()
            return UniFiInformResult(changed=True, storage=self.storage)
        if response_type == "upgrade":
            LOGGER.info("UniFi controller requested firmware upgrade to %s", decoded.get("version"))
        if response_type == "setparam":
            changed = self._handle_mgmt_cfg(decoded)

        changed = self._update_cfgversion(decoded.get("cfgversion")) or changed

        if decoded.get("interval") is not None:
            try:
                interval = max(1.0, float(decoded["interval"]))
            except (TypeError, ValueError):
                interval = None

        if isinstance(decoded.get("system_cfg"), str):
            LOGGER.debug("UniFi controller returned system_cfg (%s bytes)", len(decoded["system_cfg"]))

        return UniFiInformResult(
            changed=changed,
            interval=interval,
            storage=self.storage if changed else None,
        )

    def _handle_mgmt_cfg(self, decoded: dict[str, Any]) -> bool:
        mgmt_cfg = decoded.get("mgmt_cfg")
        if not isinstance(mgmt_cfg, str):
            return False

        cfg = _parse_kv_config(mgmt_cfg)
        changed = False

        new_key = _cfg_get(cfg, "authkey")
        if new_key and new_key != self._authkey:
            self._authkey = new_key
            self._adopted = True
            changed = True
        elif new_key:
            self._adopted = True

        changed = self._update_cfgversion(_cfg_get(cfg, "cfgversion")) or changed

        aes_gcm = _cfg_get(cfg, "use_aes_gcm")
        if aes_gcm is not None:
            use_gcm = aes_gcm.lower() == "true"
            if use_gcm != self._aes_gcm:
                self._aes_gcm = use_gcm
                changed = True

        mgmt_url = _cfg_get(cfg, "mgmt_url")
        if mgmt_url and mgmt_url != self._mgmt_url:
            self._mgmt_url = mgmt_url
            changed = True

        inform_url = _cfg_get(cfg, "servers.1.url", "inform_url")
        if inform_url and _is_inform_endpoint(inform_url) and inform_url != self._inform_url:
            self._inform_url = inform_url
            changed = True

        return changed

    def _update_cfgversion(self, value: Any) -> bool:
        if value is None:
            return False
        cfgversion = str(value)
        if cfgversion and cfgversion != self._cfgversion:
            self._cfgversion = cfgversion
            return True
        return False

    def _reset(self) -> None:
        self._authkey = DEFAULT_AUTHKEY
        self._cfgversion = "0000000000000000"
        self._inform_url = self._default_inform_url
        self._mgmt_url = ""
        self._aes_gcm = False
        self._adopted = False

    def _mac_for_data(self, data: dict[str, Any]) -> str:
        mac = _normalise_mac(str(_web_device(data).get("RootMacAddress") or ""))
        if mac:
            self._mac = mac
            return mac
        if self._mac:
            return self._mac
        seed = str(_device_status(data).get("SerialNumber") or _web_device(data).get("SerialNumber") or "nokia")
        digest = hashlib.sha1(seed.encode()).digest()
        self._mac = "02:" + ":".join(f"{byte:02x}" for byte in digest[:5])
        return self._mac

    def _payload(self, data: dict[str, Any], mac: str) -> dict[str, Any]:
        if not self._adopted:
            return _default_payload(data, mac, self._inform_url)
        return _adopted_payload(
            data,
            mac,
            self._inform_url,
            self._authkey,
            self._cfgversion,
            self._aes_gcm,
            self._geo,
        )

    async def _ensure_geo(self, data: dict[str, Any]) -> bool:
        current_ip = _public_ip_from_data(data)
        lookup_key = current_ip or "__initial__"
        needs_lookup = False

        if current_ip and current_ip not in {self._geo_ip, self._geo_lookup_key}:
            needs_lookup = True
        elif not self._geo and self._geo_lookup_key != lookup_key:
            needs_lookup = True

        if not needs_lookup:
            return False

        self._geo_lookup_key = lookup_key
        geo = await self._fetch_geo()
        if not geo:
            return False

        self._geo = geo
        self._geo_ip = current_ip or str(geo.get("address") or "")
        self._geo_lookup_key = self._geo_ip or lookup_key
        return True

    async def _fetch_geo(self) -> dict[str, Any] | None:
        try:
            async with self._session.get(GEO_URL, timeout=5) as response:
                if response.status >= 400:
                    LOGGER.debug("UniFi geo lookup returned HTTP %s", response.status)
                    return None
                payload = await response.json(content_type=None)
        except (asyncio.TimeoutError, ClientError, ValueError, TypeError) as err:
            LOGGER.debug("UniFi geo lookup failed: %s", err)
            return None

        if not isinstance(payload, dict):
            return None
        geo = _normalise_geo(payload)
        if not geo:
            return None
        LOGGER.debug("Updated UniFi geo info from %s: %s", GEO_URL, geo)
        return geo


def _default_payload(data: dict[str, Any], mac: str, inform_url: str) -> dict[str, Any]:
    return {
        "_type": "inform",
        "adopted": False,
        "anon_id": hashlib.sha1(_mac_bytes(mac)).hexdigest()[:24],
        "cfgversion": "0000000000000000",
        "default": True,
        "disabled": False,
        "discovered_via": "inform",
        "displayable_version": DISPLAYABLE_VERSION,
        "firmware": FIRMWARE_VERSION,
        "firmware_version": FIRMWARE_VERSION,
        "hostname": _hostname(data),
        "inform_ip": _ip_address(data),
        "inform_url": inform_url,
        "ip": _ip_address(data),
        "is_default": True,
        "mac": mac,
        "model": MODEL,
        "model_display": MODEL_DISPLAY,
        "model_name": MODEL_DISPLAY,
        "required_version": FIRMWARE_VERSION,
        "serial": _serial(mac),
        "state": 1,
        "status": "pending",
        "type": DEVICE_TYPE,
        "version": FIRMWARE_VERSION,
        "x_aes_gcm": False,
        "x_authkey": DEFAULT_AUTHKEY,
        "x_fingerprint": "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
    }


def _adopted_payload(
    data: dict[str, Any],
    mac: str,
    inform_url: str,
    authkey: str,
    cfgversion: str,
    aes_gcm: bool,
    geo: dict[str, Any],
) -> dict[str, Any]:
    now = int(time.time())
    rx_bytes = _as_int(_generic(data, "BytesReceived"), 0)
    tx_bytes = _as_int(_generic(data, "BytesSent"), 0)
    uptime = _as_int(_web_device(data).get("UpTime"), 120)
    rx_packets = max(1200, rx_bytes // 1024)
    tx_packets = max(2400, tx_bytes // 1024)
    ip_address = _ip_address(data)
    netmask = DEFAULT_NETMASK
    gateway = ip_address
    mem_total = _as_int(_web_nested(data, "mem_info", "Total"), 262144)
    mem_free = _as_int(_web_nested(data, "mem_info", "Free"), max(0, mem_total - 98304))
    mem_used = max(0, mem_total - mem_free)
    mem_percent = int((mem_used / mem_total) * 100) if mem_total else 0
    cpu_percent = _as_int(_web_nested(data, "cpu_usageinfo", "CPUUsage"), 0)

    system_stats = {
        "cpu": cpu_percent,
        "loadavg_1": "0.00",
        "loadavg_5": "0.00",
        "loadavg_15": "0.00",
        "mem": mem_percent,
        "mem_buffer": 0,
        "mem_total": mem_total,
        "mem_used": mem_used,
        "memory": mem_percent,
        "uptime": uptime,
    }
    iface = _interface_entry(mac, ip_address, netmask, gateway, rx_bytes, tx_bytes, rx_packets, tx_packets, uptime)
    uplink = _uplink_entry(rx_bytes, tx_bytes, rx_packets, tx_packets, uptime, netmask, gateway)

    payload = {
        "_type": "inform",
        "architecture": "arm",
        "adopted": True,
        "anon_id": hashlib.sha1(_mac_bytes(mac)).hexdigest()[:24],
        "board_rev": 1,
        "bytes": rx_bytes + tx_bytes,
        "cfgversion": cfgversion,
        "config_network": {"type": "dhcp"},
        "connect_request_ip": ip_address,
        "connect_request_port": "0",
        "default": False,
        "disabled": False,
        "discovered_via": "inform",
        "displayable_version": DISPLAYABLE_VERSION,
        "fingerprint": "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
        "firmware": FIRMWARE_VERSION,
        "firmware_version": FIRMWARE_VERSION,
        "gateway": gateway,
        "gateway_ip": gateway,
        "gateway_mac": mac,
        "geo_info": _provider_info(data, geo),
        "has_fan": False,
        "has_temperature": False,
        "hostname": _hostname(data),
        "if_table": [iface],
        "inform_ip": ip_address,
        "inform_url": inform_url,
        "interface_table": [{"name": "br0", "ip": ip_address, "netmask": netmask}],
        "internet": True,
        "ip": ip_address,
        "ipv4_address": ip_address,
        "ipv4_gateway": gateway,
        "ipv4_netmask": netmask,
        "ipv4_primary_dns": gateway,
        "ipv4_secondary_dns": DEFAULT_DNS,
        "is_default": False,
        "isolated": False,
        "kernel_version": KERNEL_VERSION,
        "lldp_table": [_lldp_entry(mac)],
        "mac": mac,
        "mbb": _mbb_payload(data, ip_address, netmask, gateway, rx_bytes, tx_bytes, now, geo),
        "model": MODEL,
        "model_display": MODEL_DISPLAY,
        "model_in_eol": False,
        "model_in_lts": False,
        "model_name": MODEL_DISPLAY,
        "netmask": netmask,
        "network_table": [
            _network_entry("LAN", ip_address, gateway, rx_bytes, tx_bytes),
            _network_entry("WAN_5G", ip_address, gateway, rx_bytes, tx_bytes),
        ],
        "port_table": [_port_entry(mac, ip_address, netmask, rx_bytes, tx_bytes, rx_packets, tx_packets, uptime)],
        "required_version": FIRMWARE_VERSION,
        "rx_bytes": rx_bytes,
        "rx_bytes-r": 0,
        "serial": _serial(mac),
        "start_connected_millis": now * 1000,
        "start_disconnected_millis": 0,
        "startup_timestamp": now - uptime,
        "state": 2,
        "status": "connected",
        "status_details": "connected",
        "sys_stats": {
            "loadavg_1": "0.00",
            "loadavg_5": "0.00",
            "loadavg_15": "0.00",
            "mem_buffer": 0,
            "mem_total": mem_total,
            "mem_used": mem_used,
        },
        "system-stats": system_stats,
        "system_stats": system_stats,
        "gw_system-stats": system_stats,
        "time": now,
        "tx_bytes": tx_bytes,
        "tx_bytes-r": 0,
        "type": DEVICE_TYPE,
        "unsupported": False,
        "uplink": uplink,
        "uplink_table": [uplink],
        "uptime": uptime,
        "uptime_stats": _uptime_stats(uptime),
        "version": FIRMWARE_VERSION,
        "wan_magic_stats": {"downtime": 0, "latency": 25, "uptime": uptime},
        "x_aes_gcm": aes_gcm,
        "x_authkey": authkey,
        "x_fingerprint": "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
        "x_has_ssh_hostkey": True,
    }
    return payload


def _mbb_payload(
    data: dict[str, Any],
    ip_address: str,
    netmask: str,
    gateway: str,
    rx_bytes: int,
    tx_bytes: int,
    now: int,
    geo: dict[str, Any],
) -> dict[str, Any]:
    radio = _radio_data(data)
    carrier = str(radio["carrier"] or "")
    asn = _geo_asn(geo)
    sim1_iccid = str(_sim_cfg(data, "ICCID") or "")
    apn = {
        "apn": str(_network_cfg(data, "APN") or "internet"),
        "auth_type": "NONE",
        "auth-type": "NONE",
        "carrier_id": carrier,
        "password": "",
        "pdp_type": "IPv4v6",
        "roaming": _truthy(_generic(data, "RoamingStatus")),
        "username": "",
        "valid": True,
    }
    connection_info = {"asn": asn, "inet_state": 1, "ip_type": "ipv4", "timestamp": now}
    sim1 = {
        "active": True,
        "asn": asn,
        "card_present": bool(sim1_iccid),
        "connection_info": connection_info,
        "current_apn": apn,
        "data_limited": False,
        "data_warning": False,
        "default_apn": apn,
        "display_state": "operational" if sim1_iccid else "no-sim",
        "esim": False,
        "gid1": "",
        "iccid": sim1_iccid,
        "initial_slot_card_read_done": True,
        "incompatible": False,
        "mcc": radio["mcc"],
        "mnc": radio["mnc"],
        "notified": False,
        "notify": False,
        "operation_in_progress": False,
        "pin": "",
        "pin_blocked": False,
        "pin_lock": False,
        "pin_tries_remaining": 3,
        "pin_verified": True,
        "puk_tries_remaining": 10,
        "reject_info": "",
        "rxbytes": rx_bytes,
        "slot": 1,
        "slot_init_eta": 0,
        "spn": carrier,
        "txbytes": tx_bytes,
    }
    return {
        "mode": "failover",
        "primary_slot": 1,
        "active_slot": 1,
        "state": "ready",
        "geo_info": _mbb_geo_info(geo, carrier),
        "imei": str(_network_cfg(data, "IMEI") or ""),
        "ip_settings": {
            "ipv4_address": ip_address,
            "ipv4_gateway": gateway,
            "ipv4_netmask": netmask,
            "ipv4_primary_dns": gateway,
            "ipv4_secondary_dns": DEFAULT_DNS,
        },
        "radio": {
            "band": radio["band"],
            "cell_id": radio["cell_id"],
            "channel": radio["channel"],
            "hplmn_denied": False,
            "hplmn_serving": True,
            "mcc": radio["mcc"],
            "mcc_cc2": "",
            "mnc": radio["mnc"],
            "mode": "auto",
            "networkoperator": carrier,
            "rat": radio["rat"],
            "rsrp": radio["rsrp"],
            "rsrp-nr": radio["rsrp"],
            "rscp": radio["rscp"],
            "rsrq": radio["rsrq"],
            "rsrq-nr": radio["rsrq"],
            "rssi": radio["rssi"],
            "rx_chan": radio["channel"],
            "signal": radio["signal"],
            "signal_percent": radio["percent"],
            "snr": radio["snr"],
            "snr-nr": radio["snr"],
            "tx_chan": radio["channel"],
        },
        "sim": [sim1],
    }


def _radio_data(data: dict[str, Any]) -> dict[str, Any]:
    nr = _first_item(data, "cell_stat_5G")
    lte = _first_item(data, "cell_stat_lte")
    use_nr = any(nr.get(key) not in (None, "") for key in ("RSRPCurrent", "AttachedCellNci", "Band"))
    source = nr if use_nr else lte
    rsrp = _radio_int(source.get("RSRPCurrent"), lte.get("RSRPCurrent"), default=-100)
    rssi = _radio_int(source.get("RSSICurrent"), lte.get("RSSICurrent"), default=rsrp)
    signal = rsrp
    percent = max(0, min(100, int(((rsrp + 120) / 50) * 100)))
    plmn = str(source.get("PLMNID") or lte.get("PLMNID") or "")
    return {
        "band": str(source.get("Band") or ""),
        "bars": max(0, min(5, round(percent / 20))),
        "carrier": _carrier_name(
            source,
            lte,
            _first_item(data, "cell_stat_generic"),
            _first_statistics_item(data, "network_cfg"),
            _first_statistics_item(data, "sim_cfg"),
        )
        or "",
        "cell_id": _as_int(source.get("AttachedCellNci") or source.get("Cellid"), 0),
        "channel": _as_int(source.get("AttachedCellNRArfcn") or source.get("AttachedCellEArfcn"), 0),
        "mcc": _as_int(plmn[:3], 0) if len(plmn) >= 3 else 0,
        "mnc": _as_int(plmn[3:], 0) if len(plmn) > 3 else 0,
        "percent": percent,
        "rat": "5G NSA" if use_nr else str(_generic(data, "CurrentAccessTechnology") or "LTE"),
        "rscp": _radio_int(source.get("RSCPCurrent"), lte.get("RSCPCurrent"), default=-85),
        "rsrp": rsrp,
        "rsrq": _radio_int(source.get("RSRQCurrent"), lte.get("RSRQCurrent"), default=-9),
        "rssi": rssi,
        "signal": signal,
        "snr": _radio_int(source.get("SNRCurrent"), lte.get("SNRCurrent"), default=0),
    }


def _interface_entry(
    mac: str,
    ip_address: str,
    netmask: str,
    gateway: str,
    rx_bytes: int,
    tx_bytes: int,
    rx_packets: int,
    tx_packets: int,
    uptime: int,
) -> dict[str, Any]:
    return {
        "full_duplex": True,
        "gateway_ip": gateway,
        "ip": ip_address,
        "mac": mac,
        "name": "br0",
        "netmask": netmask,
        "num_port": 1,
        "rx_broadcast": 0,
        "rx_bytes": rx_bytes,
        "rx_bytes-r": 0,
        "rx_dropped": 0,
        "rx_errors": 0,
        "rx_multicast": 0,
        "rx_packets": rx_packets,
        "rx_rate": 0,
        "speed": 1000,
        "tx_broadcast": 0,
        "tx_bytes": tx_bytes,
        "tx_bytes-r": 0,
        "tx_dropped": 0,
        "tx_errors": 0,
        "tx_multicast": 0,
        "tx_packets": tx_packets,
        "tx_rate": 0,
        "up": True,
        "uptime": uptime,
    }


def _port_entry(mac: str, ip_address: str, netmask: str, rx_bytes: int, tx_bytes: int, rx_packets: int, tx_packets: int, uptime: int) -> dict[str, Any]:
    return {
        "autoneg": True,
        "full_duplex": True,
        "ifname": "br0",
        "ip": ip_address,
        "is_uplink": True,
        "mac": mac,
        "mac_table": [],
        "media": "GE",
        "name": "br0",
        "netmask": netmask,
        "op_mode": "switch",
        "port_idx": 1,
        "portconf_id": "1",
        "port_poe": False,
        "rx_bytes": rx_bytes,
        "rx_bytes-r": 0,
        "rx_dropped": 0,
        "rx_errors": 0,
        "rx_packets": rx_packets,
        "rx_rate": 0,
        "speed": 1000,
        "speed_caps": [10, 100, 1000, 2500],
        "stp_state": "forwarding",
        "tx_bytes": tx_bytes,
        "tx_bytes-r": 0,
        "tx_dropped": 0,
        "tx_errors": 0,
        "tx_packets": tx_packets,
        "tx_rate": 0,
        "up": True,
    }


def _uplink_entry(rx_bytes: int, tx_bytes: int, rx_packets: int, tx_packets: int, uptime: int, netmask: str, gateway: str) -> dict[str, Any]:
    return {
        "full_duplex": True,
        "gateways": [gateway],
        "latency": 25,
        "max_speed": 1000,
        "media": "GE",
        "name": "br0",
        "nameservers": [gateway],
        "netmask": netmask,
        "port_idx": 1,
        "rx_bytes": rx_bytes,
        "rx_bytes-r": 0,
        "rx_packets": rx_packets,
        "rx_rate": 0,
        "speed": 1000,
        "tx_bytes": tx_bytes,
        "tx_bytes-r": 0,
        "tx_packets": tx_packets,
        "tx_rate": 0,
        "type": "wire",
        "uptime": uptime,
    }


def _lldp_entry(mac: str) -> dict[str, Any]:
    return {
        "chassis_descr": _hostname({}),
        "chassis_id": mac,
        "is_wired": True,
        "local_port_idx": 1,
        "local_port_name": "br0",
        "port_descr": "Port 1",
        "port_id": "Port 1",
    }


def _network_entry(name: str, ip_address: str, gateway: str, rx_bytes: int, tx_bytes: int) -> dict[str, Any]:
    return {
        "address": ip_address,
        "addresses": [ip_address],
        "gateways": [gateway],
        "name": name,
        "nameservers": [gateway],
        "stats": {"rx_bytes": rx_bytes, "rx_rate": 0, "tx_bytes": tx_bytes, "tx_rate": 0},
    }


def _uptime_stats(uptime: int) -> dict[str, Any]:
    monitor = {"availability": 100, "latency_average": 25, "target": "8.8.8.8"}
    wan = {"alerting_monitors": [], "downtime": 0, "latency_average": 25, "monitors": [monitor], "uptime": uptime}
    return {**wan, "WAN": dict(wan), "WAN2": dict(wan), "WAN_UNBOUND": dict(wan)}


def _provider_info(data: dict[str, Any], geo: dict[str, Any]) -> dict[str, Any]:
    carrier = _radio_data(data)["carrier"] or "Unknown"
    provider = {"asn": _geo_asn(geo), "isp_name": _geo_isp(geo, carrier)}
    return {"WAN": dict(provider), "WAN2": dict(provider)}


def _mbb_geo_info(geo: dict[str, Any], fallback_isp: str) -> dict[str, Any]:
    info: dict[str, Any] = {
        "address": str(geo.get("address") or ""),
        "isp": _geo_isp(geo, fallback_isp),
    }
    for key in (
        "continent_code",
        "country_code",
        "country_name",
        "city",
        "latitude",
        "longitude",
        "accuracy",
        "asn",
        "organization",
        "timezone",
    ):
        value = geo.get(key)
        if value not in (None, ""):
            info[key] = value
    return info


def _carrier_name(*records: dict[str, Any]) -> str | None:
    for record in records:
        for key in CARRIER_KEYS:
            carrier = _clean_carrier_name(record.get(key))
            if carrier:
                return carrier
    return None


def _clean_carrier_name(value: Any) -> str | None:
    if value in (None, "") or isinstance(value, (bool, int, float)):
        return None
    text = re.sub(r"\s+", " ", str(value)).strip()
    if not text or not any(char.isalpha() for char in text):
        return None
    if _looks_like_data_amount(text) or _looks_like_address(text):
        return None
    return text


def _looks_like_data_amount(value: str) -> bool:
    if "byte" in value.lower():
        return True
    return bool(
        re.fullmatch(
            r"[+-]?\d+(?:\.\d+)?\s*(?:b|bytes?|ki?b|mi?b|gi?b|ti?b)",
            value.strip(),
            re.IGNORECASE,
        )
    )


def _looks_like_address(value: str) -> bool:
    return _normalise_mac(value) is not None or _public_ip_from_value(value) is not None


def _radio_int(*values: Any, default: int) -> int:
    for value in values:
        parsed = _as_optional_int(value)
        if parsed is not None:
            return parsed
    return default


def _geo_asn(geo: dict[str, Any]) -> int:
    return _as_int(geo.get("asn"), 0)


def _geo_isp(geo: dict[str, Any], fallback: str) -> str:
    return str(geo.get("isp") or geo.get("organization") or fallback or "Unknown")


def _normalise_geo(value: dict[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in GEO_KEYS if value.get(key) not in (None, "")}


def _public_ip_from_data(data: dict[str, Any]) -> str | None:
    records = [
        _web_device(data),
        _device_status(data),
        _first_item(data, "cell_stat_generic"),
        _first_item(data, "cell_stat_lte"),
        _first_item(data, "cell_stat_5G"),
        _first_statistics_item(data, "network_cfg"),
        _first_statistics_item(data, "sim_cfg"),
    ]
    for record in records:
        for key in PUBLIC_IP_KEYS:
            ip = _public_ip_from_value(record.get(key))
            if ip:
                return ip
        for key, value in record.items():
            if not isinstance(key, str):
                continue
            key_lower = key.lower()
            if (
                key_lower.endswith("_ip")
                or key_lower.endswith("ipaddress")
                or key_lower in {"ip", "ipaddr", "wanip", "wan_ip", "ipv4", "ipv4address"}
            ):
                ip = _public_ip_from_value(value)
                if ip:
                    return ip
    return None


def _public_ip_from_value(value: Any) -> str | None:
    if value in (None, ""):
        return None
    for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(value)):
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if ip.is_global:
            return str(ip)
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


def _as_optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    match = re.search(r"-?\d+", str(value))
    return int(match.group(0)) if match else None


def _encode_tnbu(payload: dict[str, Any], mac: str, authkey: str, gcm: bool) -> bytes:
    body = zlib.compress(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    flags = FLAG_ENCRYPTED | FLAG_ZLIB | (FLAG_GCM if gcm else 0)
    iv = os.urandom(16)
    encrypted_len = len(body) + 16 if gcm else len(_pkcs7_pad(body))
    header = struct.pack(">4sI6sH16sII", MAGIC, PACKET_VERSION, _mac_bytes(mac), flags, iv, PAYLOAD_VERSION_JSON, encrypted_len)
    if gcm:
        cipher = AES.new(_key_bytes(authkey), AES.MODE_GCM, nonce=iv, mac_len=16)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(body)
        return header + ciphertext + tag
    cipher = AES.new(_key_bytes(authkey), AES.MODE_CBC, iv)
    return header + cipher.encrypt(_pkcs7_pad(body))


def _decode_tnbu(packet: bytes, authkeys: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    magic, packet_version, hwaddr, flags, iv, payload_version, payload_len = struct.unpack(">4sI6sH16sII", packet[:40])
    if magic != MAGIC or flags & FLAG_SNAPPY:
        raise UniFiInformError("Unsupported UniFi TNBU response")
    payload = packet[40 : 40 + payload_len]
    last_error: Exception | None = None
    for authkey in authkeys:
        try:
            plain = payload
            if flags & FLAG_GCM:
                cipher = AES.new(_key_bytes(authkey), AES.MODE_GCM, nonce=iv, mac_len=16)
                cipher.update(packet[:40])
                plain = cipher.decrypt_and_verify(payload[:-16], payload[-16:])
            else:
                cipher = AES.new(_key_bytes(authkey), AES.MODE_CBC, iv)
                plain = _pkcs7_unpad(cipher.decrypt(payload))
            if flags & FLAG_ZLIB:
                plain = zlib.decompress(plain)
            return json.loads(plain.decode()), {
                "packet_version": packet_version,
                "mac": ":".join(f"{byte:02x}" for byte in hwaddr),
                "flags": flags,
                "payload_version": payload_version,
            }
        except Exception as err:
            last_error = err
    raise UniFiInformError(f"Could not decode UniFi response: {last_error}")


def _key_bytes(authkey: str) -> bytes:
    return bytes.fromhex(authkey)


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("invalid padding")
    return data[:-pad_len]


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":"))


def _normalise_mac(value: str) -> str | None:
    raw = value.strip().replace("-", ":").lower()
    if ":" not in raw:
        raw = raw.replace(".", "")
        if len(raw) == 12:
            raw = ":".join(raw[i : i + 2] for i in range(0, 12, 2))
    parts = raw.split(":")
    if len(parts) == 6 and all(re.fullmatch(r"[0-9a-f]{2}", part) for part in parts):
        return raw
    return None


def _serial(mac: str) -> str:
    return mac.replace(":", "").upper()


def _hostname(data: dict[str, Any]) -> str:
    return str(_web_device(data).get("X_ASB_COM_FriendlyName") or "Nokia-FastMile")


def _ip_address(data: dict[str, Any]) -> str:
    value = str(_web_device(data).get("IPAddress") or "")
    return value if value else DEFAULT_GATEWAY_IP


def _first_item(data: dict[str, Any], group: str) -> dict[str, Any]:
    cell_status = data.get("cell_status")
    if not isinstance(cell_status, dict):
        return {}
    value = cell_status.get(group)
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    return {}


def _first_statistics_item(data: dict[str, Any], group: str) -> dict[str, Any]:
    statistics_status = data.get("statistics_status")
    if not isinstance(statistics_status, dict):
        return {}
    value = statistics_status.get(group)
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    return {}


def _device_status(data: dict[str, Any]) -> dict[str, Any]:
    value = data.get("device_status")
    return value if isinstance(value, dict) else {}


def _web_device(data: dict[str, Any]) -> dict[str, Any]:
    value = data.get("web_device_status")
    return value if isinstance(value, dict) else {}


def _web_nested(data: dict[str, Any], group: str, key: str) -> Any:
    value = _web_device(data).get(group)
    if isinstance(value, dict):
        return value.get(key)
    return None


def _generic(data: dict[str, Any], key: str) -> Any:
    return _first_item(data, "cell_stat_generic").get(key)


def _network_cfg(data: dict[str, Any], key: str) -> Any:
    return _first_statistics_item(data, "network_cfg").get(key)


def _sim_cfg(data: dict[str, Any], key: str) -> Any:
    return _first_statistics_item(data, "sim_cfg").get(key)


def _as_int(value: Any, default: int) -> int:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    match = re.search(r"-?\d+", str(value))
    return int(match.group(0)) if match else default


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "roaming"}


def _parse_kv_config(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def _cfg_get(cfg: dict[str, str], *names: str) -> str | None:
    for name in names:
        if name in cfg:
            return cfg[name]
        prefixed = f"mgmt.{name}"
        if prefixed in cfg:
            return cfg[prefixed]
    return None


def _is_inform_endpoint(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.path.rstrip("/") == "/inform"
