"""Client for Nokia FastMile gateway app endpoints."""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from typing import Any

from aiohttp import ClientError, ClientResponse, ClientSession
from yarl import URL

from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError


APP_USER_AGENT = "App/3.260112.00 (iPhone; iOS 26.4.2; Scale/3.00)"
WEB_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Safari/605.1.15"
)

LOGGER = logging.getLogger(__name__)


class NokiaFastMileError(HomeAssistantError):
    """Base Nokia FastMile error."""


class NokiaFastMileAuthError(NokiaFastMileError):
    """Authentication failed."""


class NokiaFastMileClient:
    """Async client for Nokia FastMile gateways."""

    def __init__(
        self,
        session: ClientSession,
        host: str,
        port: int,
        username: str,
        password: str,
        use_ssl: bool,
    ) -> None:
        """Initialize the client."""
        self._session = session
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._scheme = "https" if use_ssl else "http"
        self._cookies: dict[str, str] = {}
        self._web_sid: str | None = None
        self._web_token: str | None = None

    @property
    def _base_url(self) -> URL:
        """Return the gateway base URL."""
        return URL.build(scheme=self._scheme, host=self._host, port=self._port)

    @property
    def _headers(self) -> dict[str, str]:
        """Return headers matching the Nokia app."""
        headers = {
            "Host": self._host,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
            "User-Agent": APP_USER_AGENT,
            "Accept-Language": "en-NZ;q=1",
        }
        if self._cookies:
            headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in self._cookies.items()
            )
        else:
            headers["Cookie"] = ";"
        return headers

    @property
    def _web_headers(self) -> dict[str, str]:
        """Return headers matching the Nokia web UI."""
        headers = {
            "Host": self._host,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Language": "en-NZ,en-AU;q=0.9,en;q=0.8",
            "User-Agent": WEB_USER_AGENT,
            "Referer": str(self._base_url / ""),
        }
        if sid := self._web_sid:
            headers["Cookie"] = f"sid={sid}"
        else:
            headers["Cookie"] = ";"
        return headers

    @property
    def _web_post_headers(self) -> dict[str, str]:
        """Return web UI POST headers."""
        headers = self._web_headers
        headers["Origin"] = str(self._base_url)
        return headers

    async def async_login(self) -> dict[str, Any]:
        """Log in and store returned cookies."""
        payload = {
            "name": self._username,
            "pswd": self._password,
            "srip": "",
        }
        data = await self._request("POST", "login_app.cgi", data=payload, auth=False)

        if data.get("result") != 0:
            raise NokiaFastMileAuthError(
                f"Gateway rejected login with result {data.get('result')}"
            )

        cookies = data.get("cookie")
        if isinstance(cookies, dict):
            for name in ("sid", "lsid"):
                value = cookies.get(name)
                if isinstance(value, str) and "=" in value:
                    cookie_name, cookie_value = value.split("=", 1)
                    self._cookies[cookie_name] = cookie_value

        if not {"sid", "lsid"}.issubset(self._cookies):
            raise NokiaFastMileAuthError("Gateway did not return session cookies")

        return data

    async def async_web_login(self) -> None:
        """Log in to the web UI and store the returned web session."""
        LOGGER.debug("Starting Nokia FastMile web UI login")
        nonce_data = await self._request(
            "POST",
            "login_web_app.cgi?nonce",
            data={"userName": self._username},
            headers=self._web_post_headers,
            auth=False,
        )
        nonce = str(nonce_data["nonce"])
        random_key = str(nonce_data["randomKey"])
        iterations = int(nonce_data.get("iterations", 1))

        userhash = _sha256url(self._username, nonce)
        salt_data = await self._request(
            "POST",
            "login_web_app.cgi?salt",
            data={
                "userhash": userhash,
                "nonce": _base64url_escape(nonce),
            },
            headers=self._web_post_headers,
            auth=False,
        )
        salt = str(salt_data["alati"])
        password_hash = _web_password_hash(salt, self._password, iterations)
        response_hash = _sha256url(
            _sha256(self._username, password_hash.lower()),
            nonce,
        )

        await self._request(
            "GET",
            "main_web_app.cgi",
            headers=self._web_headers,
            auth=False,
        )

        login_data = await self._request(
            "POST",
            "login_web_app.cgi",
            data={
                "userhash": userhash,
                "RandomKeyhash": _sha256url(random_key, nonce),
                "response": response_hash,
                "nonce": _base64url_escape(nonce),
                "enckey": _base64url_escape(_random_base64()),
                "enciv": _base64url_escape(_random_base64()),
            },
            headers=self._web_post_headers,
            auth=False,
        )

        if login_data.get("result") != 0 or not login_data.get("sid"):
            raise NokiaFastMileAuthError(
                f"Gateway rejected web login with result {login_data.get('result')}"
            )

        self._web_sid = str(login_data["sid"])
        self._web_token = str(login_data.get("token") or "")
        LOGGER.debug("Nokia FastMile web UI login succeeded")

    async def async_get_data(self) -> dict[str, object]:
        """Fetch gateway and cellular data."""
        if not self._cookies:
            await self.async_login()

        try:
            return await self._async_fetch_data()
        except NokiaFastMileAuthError:
            self._cookies.clear()
            await self.async_login()
            return await self._async_fetch_data()

    async def _async_fetch_data(self) -> dict[str, object]:
        """Fetch all integration data using the current cookies."""
        device_status = await self._request("GET", "device_status_app.cgi")
        cell_status = await self._request("GET", "cell_status_app.cgi")
        web_device_status: dict[str, Any] = {}
        statistics_status: dict[str, Any] = {}
        try:
            if not self._web_sid:
                await self.async_web_login()
            LOGGER.debug("Fetching Nokia FastMile web device status")
            web_device_status = await self._request(
                "GET",
                "device_status_web_app.cgi?getroot",
                headers=self._web_headers,
            )
            LOGGER.debug("Fetching Nokia FastMile web statistics status")
            statistics_status = await self._request(
                "GET",
                "fastmile_statistics_status_web_app.cgi",
                headers=self._web_headers,
            )
        except NokiaFastMileAuthError:
            LOGGER.debug("Nokia FastMile web session expired during status fetch")
            self._web_sid = None
            self._web_token = None
        except NokiaFastMileError as err:
            LOGGER.debug("Could not fetch Nokia FastMile web status: %s", err)
        return {
            "device_status": device_status,
            "cell_status": cell_status,
            "web_device_status": web_device_status,
            "statistics_status": statistics_status,
        }

    async def _request(
        self,
        method: str,
        path: str,
        *,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        auth: bool = True,
    ) -> dict[str, Any]:
        """Request a JSON endpoint."""
        url = self._url(path)
        try:
            async with self._session.request(
                method,
                url,
                data=data,
                headers=headers or self._headers,
                allow_redirects=True,
            ) as response:
                return await self._handle_response(response, auth, method, path)
        except NokiaFastMileAuthError:
            raise
        except ClientError as err:
            raise NokiaFastMileError(f"Could not connect to Nokia gateway: {err}") from err

    def _url(self, path: str) -> URL:
        """Return an endpoint URL, preserving query strings."""
        return self._base_url.join(URL(path))

    async def _handle_response(
        self,
        response: ClientResponse,
        auth: bool,
        method: str,
        path: str,
    ) -> dict[str, Any]:
        """Decode and validate a gateway response."""
        if response.status in (401, 403):
            raise NokiaFastMileAuthError("Gateway session expired")
        if response.status >= 400:
            text = await response.text()
            LOGGER.debug(
                "Nokia FastMile request failed: %s %s returned HTTP %s, "
                "content_type=%s, body=%r",
                method,
                path,
                response.status,
                response.content_type,
                text[:500],
            )
            raise NokiaFastMileError(f"Gateway returned HTTP {response.status}")

        try:
            data = await response.json(content_type=None)
        except ValueError as err:
            text = await response.text()
            raise NokiaFastMileError(
                f"Gateway returned invalid JSON: {text[:120]}"
            ) from err

        if auth and data.get("result") not in (None, 0):
            raise NokiaFastMileAuthError("Gateway session expired")

        return data


async def async_validate_credentials(client: NokiaFastMileClient) -> dict[str, Any]:
    """Validate credentials and return device status."""
    try:
        await client.async_login()
        return await client._request("GET", "device_status_app.cgi")
    except NokiaFastMileAuthError as err:
        raise ConfigEntryAuthFailed(str(err)) from err


def _base64url_escape(value: str) -> str:
    """Escape base64 the same way the Nokia web UI does."""
    return value.replace("+", "-").replace("/", "_").replace("=", ".")


def _sha256(left: str, right: str) -> str:
    """Return base64 SHA-256 of two values joined by a colon."""
    digest = hashlib.sha256(f"{left}:{right}".encode()).digest()
    return base64.b64encode(digest).decode()


def _sha256url(left: str, right: str) -> str:
    """Return Nokia web UI URL-safe base64 SHA-256."""
    return _base64url_escape(_sha256(left, right))


def _web_password_hash(salt: str, password: str, iterations: int) -> str:
    """Return the iterated password hash used by FWA web login."""
    if iterations < 1:
        return f"{salt}{password}"

    value = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    for _ in range(1, iterations):
        value = hashlib.sha256(bytes.fromhex(value)).hexdigest()
    return value


def _random_base64() -> str:
    """Return a random 16-byte value as standard base64."""
    return base64.b64encode(secrets.token_bytes(16)).decode()
