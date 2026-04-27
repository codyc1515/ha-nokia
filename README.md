# Nokia FastMile for Home Assistant

Custom integration domain: `nokia`

This integration polls Nokia FastMile gateways locally over the app CGI endpoints on port 80.

## Install

Copy `custom_components/nokia` into your Home Assistant `custom_components` directory, then restart Home Assistant.

Add the integration from **Settings > Devices & services > Add integration > Nokia FastMile**.

## Configuration

Default host: `www.webgui.nokiawifi.com`

Other expected hosts:

- `nokiadevice.local`
- your gateway IP address

Default port: `80`

Default username: `admin`

The password is required. HTTPS is optional and disabled by default because the captured Nokia app traffic uses `http` on port 80.

## Sensors

The integration creates diagnostic sensors from:

- `device_status_app.cgi` for device registry metadata
- `cell_status_app.cgi` for cellular status
- `device_status_web_app.cgi?getroot` for additional device diagnostics
- `fastmile_statistics_status_web_app.cgi` for network and SIM details

Generic sensors:

- Roaming
- Technology
- TAC
- Bytes sent
- Bytes received
- IMEI
- SIM type
- SIM status
- IMSI
- ICCID
- MSISDN
- Friendly name
- Root MAC address
- IP address
- Lot number
- CPU usage
- Memory total
- Memory free

4G and 5G sensors:

- eNB where available
- Cell
- SNR
- RSRP
- RSRQ
- RSSI where available
- Band
- Bandwidth
- PCI
- EARFCN
- Carrier
- Power where available
- CQI
- NSA where available
