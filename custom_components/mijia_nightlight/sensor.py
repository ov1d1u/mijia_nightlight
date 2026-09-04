from homeassistant.components.sensor import SensorEntity
from homeassistant.const import CONF_MAC, EntityCategory
from homeassistant.helpers.device_registry import DeviceInfo, CONNECTION_BLUETOOTH

from .const import DOMAIN, OUTGOING_MESSAGES_UPDATED_EVENT


async def async_setup_entry(hass, config_entry, async_add_entities):
    instance = hass.data[DOMAIN][config_entry.entry_id]
    async_add_entities([MJYD2SOutgoingMessagesSensor(instance, config_entry)])


class MJYD2SOutgoingMessagesSensor(SensorEntity):
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False
    _attr_icon = "mdi:message-arrow-right-outline"
    _attr_native_unit_of_measurement = "messages"

    def __init__(self, instance, config_entry):
        self._instance = instance
        self._attr_name = f"{config_entry.data['name']} Outgoing Waiting Messages"
        self._attr_unique_id = f"{config_entry.entry_id}_outgoing_waiting_messages"
        self._attr_native_value = instance.outgoing_messages_count
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, config_entry.entry_id)},
            connections={(CONNECTION_BLUETOOTH, config_entry.data[CONF_MAC])},
            name=config_entry.data["name"],
            manufacturer="Xiaomi",
            model="MJYD2S",
        )

    @property
    def name(self):
        return self._attr_name

    async def async_added_to_hass(self):
        await super().async_added_to_hass()
        self._attr_native_value = self._instance.outgoing_messages_count
        self._instance.eventbus.add_listener(
            OUTGOING_MESSAGES_UPDATED_EVENT,
            self.outgoing_messages_updated,
        )

    async def outgoing_messages_updated(self, count):
        self._attr_native_value = count
        self.async_write_ha_state()

    async def async_will_remove_from_hass(self):
        self._instance.eventbus.remove_listener(
            OUTGOING_MESSAGES_UPDATED_EVENT,
            self.outgoing_messages_updated,
        )
        await super().async_will_remove_from_hass()
