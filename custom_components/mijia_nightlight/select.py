from homeassistant.components.select import SelectEntity
from .const import DOMAIN, DEVICE_UPDATED_EVENT

async def async_setup_entry(hass, config_entry, async_add_entities):
    instance = hass.data[DOMAIN][config_entry.entry_id]
    async_add_entities([MJYD2SSelect(instance, config_entry)])


class MJYD2SSelect(SelectEntity):
    def __init__(self, instance, config_entry):
        self._instance = instance
        self._attr_assumed_state = True
        self._attr_name = f"{config_entry.data["name"]} Ambient Light Sensor Limit"
        self._attr_unique_id = f"{config_entry.entry_id}_ambient_limit"
        self._attr_current_option = None
        self._attr_translation_key = "ambient_light"
        self._attr_options = [
            "pitch_black",
            "dark",
            "dim",
            "slightly_lit",
            "bright"
        ]

        instance.eventbus.add_listener(DEVICE_UPDATED_EVENT, self.config_updated)

    @property
    def name(self):
        return self._attr_name
    
    async def async_select_option(self, option: str) -> None:
        if option == "pitch_black":
            await self._instance.set_ambient_limit(0)
        elif option == "dark":
            await self._instance.set_ambient_limit(25)
        elif option == "dim":
            await self._instance.set_ambient_limit(50)
        elif option == "slightly_lit":
            await self._instance.set_ambient_limit(75)
        elif option == "bright":
            await self._instance.set_ambient_limit(100)
        
        self._attr_current_option = option
        self.async_write_ha_state()

    async def config_updated(self, configuration):
        if configuration.ambient_limit < 25:
            self._attr_current_option = "pitch_black"
        elif configuration.ambient_limit >= 25 and configuration.ambient_limit < 50:
            self._attr_current_option = "dark"
        elif configuration.ambient_limit >= 50 and configuration.ambient_limit < 75:
            self._attr_current_option = "dim"
        elif configuration.ambient_limit >= 75 and configuration.ambient_limit < 100:
            self._attr_current_option = "slightly_lit"
        elif configuration.ambient_limit >= 100:
            self._attr_current_option = "bright"
        self.async_write_ha_state()
    
    def __del__(self):
        self._instance.eventbus.remove_listener(DEVICE_UPDATED_EVENT, self.config_updated)