from homeassistant.components.number import NumberEntity
from homeassistant.const import UnitOfTime, PERCENTAGE
from .const import DOMAIN, DEVICE_UPDATED_EVENT

NUMBER_KIND_BRIGHTNESS = "brightness"
NUMBER_KIND_DURATION = "duration"

async def async_setup_entry(hass, config_entry, async_add_entities):
    instance = hass.data[DOMAIN][config_entry.entry_id]
    async_add_entities([
        MJYD2SNumber(instance, config_entry, NUMBER_KIND_BRIGHTNESS),
        MJYD2SNumber(instance, config_entry, NUMBER_KIND_DURATION)
      ])

class MJYD2SNumber(NumberEntity):
    def __init__(self, instance, config_entry, kind):
        self._instance = instance
        self._kind = kind
        self._attr_name = f"{config_entry.data["name"]} {kind.title()}"
        self._attr_unique_id = f"{config_entry.entry_id}_{kind}"
        
        if kind == NUMBER_KIND_BRIGHTNESS:
            self._attr_native_min_value = 1
            self._attr_native_max_value = 100
            self._attr_native_step = 1
            self._attr_native_unit_of_measurement = PERCENTAGE
        elif kind == NUMBER_KIND_DURATION:
            self._attr_native_min_value = 15
            self._attr_native_max_value = 60
            self._attr_native_step = 1
            self._attr_native_unit_of_measurement = UnitOfTime.SECONDS

        instance.eventbus.add_listener(DEVICE_UPDATED_EVENT, self.config_updated)

    @property
    def name(self):
        return self._attr_name

    async def async_set_native_value(self, value: float) -> None:
        """Update the current value."""
        value = int(value)
        if self._kind == NUMBER_KIND_BRIGHTNESS:
            await self._instance.set_brightness(value)
        elif self._kind == NUMBER_KIND_DURATION:
            await self._instance.set_duration(value)
        
        self._attr_native_value = value
        self.async_write_ha_state()

    async def config_updated(self, configuration):
        if self._kind == NUMBER_KIND_BRIGHTNESS:
            self._attr_native_value = configuration.brightness
        elif self._kind == NUMBER_KIND_DURATION:
            self._attr_native_value = configuration.duration
        self.async_write_ha_state()
    
    def __del__(self):
        self._instance.eventbus.remove_listener(DEVICE_UPDATED_EVENT, self.config_updated)