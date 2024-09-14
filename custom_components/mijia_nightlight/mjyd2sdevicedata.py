from homeassistant.components.bluetooth import async_ble_device_from_address

import logging

LOGGER = logging.getLogger(__name__)

class MJYD2SDeviceData():
    def __init__(self, hass, discovery_info) -> None:
        self._discovery = discovery_info
        self._address = self._discovery.address
        self._name = self._discovery.name
        self._rssi = self._discovery.rssi
        self._hass = hass
        self._bledevice = async_ble_device_from_address(hass, self._address)

    @property
    def address(self):
        return self._address

    @property
    def name(self):
        return self._name

    @property
    def is_supported(self):
        data = self._discovery.manufacturer_data
        if data[2] + (data[3] << 8) == 0x07F6:
            return True
        return False
