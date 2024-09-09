import asyncio
import secrets
from homeassistant.components.bluetooth import async_ble_device_from_address

import logging

LOGGER = logging.getLogger(__name__)

class DeviceData():
    def __init__(self, hass, discovery_info) -> None:
        self._discovery = discovery_info
        self._supported = self._discovery.name.lower().startswith("MJYD2S")
        self._address = self._discovery.address
        self._name = self._discovery.name
        self._rssi = self._discovery.rssi
        self._hass = hass
        self._bledevice = async_ble_device_from_address(hass, self._address)

class MijiaNightlight:
    mac = None
    device = None
    client = None
    queue_in = asyncio.Queue()

    mi_token = None
    mi_random_key = secrets.token_bytes(16)
    mi_random_key_recv = None
    derived_key = None
    msg_count = 0

    def __init__(self, mac, mi_token) -> None:
        self.mac = mac
        self.mi_token = mi_token

    async def notification_handler(self, sender, data):
        short_uuid = sender.uuid.split("-")[0]
        LOGGER.debug(f"Incoming data: {short_uuid}\t{data.hex()}")
        self.queue_in.put_nowait(data)
