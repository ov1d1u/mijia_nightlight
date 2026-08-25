import logging

XIAOMI_INC = "0000fe95-0000-1000-8000-00805f9b34fb"

LOGGER = logging.getLogger(__name__)

class MJYD2SDeviceData():
    def __init__(self, hass, discovery_info) -> None:
        self._discovery = discovery_info
        self._address = self._discovery.address
        self._name = self._discovery.name
        self._rssi = self._discovery.rssi
        self._hass = hass

    @property
    def address(self):
        return self._address

    @property
    def name(self):
        return self._name

    @property
    def is_supported(self):
        data = self._discovery.service_data.get(XIAOMI_INC) 
        if data and len(data) >= 4:
            if data[2] + (data[3] << 8) == 0x07F6:
                return True
        return False
