from homeassistant.components.switch import SwitchEntity
from .const import DOMAIN, DEVICE_UPDATED_EVENT

async def async_setup_entry(hass, config_entry, async_add_entities):
    instance = hass.data[DOMAIN][config_entry.entry_id]
    async_add_entities([MJYD2SSwitch(instance, config_entry)])


class MJYD2SSwitch(SwitchEntity):
    def __init__(self, instance, config_entry):
        self._instance = instance
        self._attr_name =  config_entry.data["name"]
        self._attr_unique_id = f"{config_entry.entry_id}_switch"
        self._attr_is_on = False

        instance.eventbus.add_listener(DEVICE_UPDATED_EVENT, self.config_updated)

    @property
    def name(self):
        return self._attr_name
    
    @property
    def is_on(self):
        return self._attr_is_on

    async def async_turn_on(self, **kwargs):
        await self._instance.turn_on(refresh_configuration=True)
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs):
        await self._instance.turn_off(refresh_configuration=True)
        self.async_write_ha_state()

    async def config_updated(self, configuration):
        self._attr_is_on = configuration.is_enabled
        self.async_write_ha_state()
    
    def __del__(self):
        self._instance.eventbus.remove_listener(DEVICE_UPDATED_EVENT, self.config_updated)