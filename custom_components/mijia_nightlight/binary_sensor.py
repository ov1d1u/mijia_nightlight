from homeassistant.components.binary_sensor import BinarySensorEntity
from .const import DOMAIN, DEVICE_CONNECTED_EVENT, DEVICE_DISCONNECTED_EVENT

async def async_setup_entry(hass, config_entry, async_add_entities):
    instance = hass.data[DOMAIN][config_entry.entry_id]
    async_add_entities([MJYD2SBinarySensor(instance, config_entry)])


class MJYD2SBinarySensor(BinarySensorEntity):
    def __init__(self, instance, config_entry):
        self._instance = instance
        self._attr_name = f"{config_entry.data["name"]} Connected"
        self._attr_unique_id = f"{config_entry.entry_id}_is_connected"
        self._attr_is_on = False
        self._attr_icon = "mdi:bluetooth"

        instance.eventbus.add_listener(DEVICE_CONNECTED_EVENT, self.device_connected)
        instance.eventbus.add_listener(DEVICE_DISCONNECTED_EVENT, self.device_disconnected)

    @property
    def name(self):
        return self._attr_name
    
    @property
    def is_on(self):
        return self._attr_is_on

    async def device_connected(self, device):
        self._attr_is_on = True
        self._attr_icon = "mdi:bluetooth-connect"
        self.async_write_ha_state()

    async def device_disconnected(self, device):
        self._attr_is_on = False
        self._attr_icon = "mdi:bluetooth-off"
        self.async_write_ha_state()

    def __del__(self):
        self._instance.eventbus.remove_listener(DEVICE_CONNECTED_EVENT, self.device_connected)
        self._instance.eventbus.remove_listener(DEVICE_DISCONNECTED_EVENT, self.device_disconnected)