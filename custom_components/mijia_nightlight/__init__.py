"""The Xiaomi Motion Activated Night Light 2 integration."""

from __future__ import annotations

import logging
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform, CONF_MAC
from homeassistant.core import HomeAssistant, callback
from homeassistant.components import bluetooth
from homeassistant.components.bluetooth.match import ADDRESS, BluetoothCallbackMatcher

from .mjyd2s import MJYD2S
from .const import DOMAIN, CONF_MI_TOKEN, CONF_PERSIST_STATE

LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SWITCH, Platform.NUMBER, Platform.BINARY_SENSOR, Platform.SELECT]

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Xiaomi Motion Activated Night Light 2 from a config entry."""

    mac = entry.options.get(CONF_MAC, None) or entry.data.get(CONF_MAC, None)
    mi_token = entry.options.get(CONF_MI_TOKEN, None) or entry.data.get(CONF_MI_TOKEN, None)
    persist_state = entry.options.get(CONF_PERSIST_STATE, False) or entry.data.get(CONF_PERSIST_STATE, False)

    instance = MJYD2S(hass, mac, mi_token, persist_state)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = instance

    async def _connect_and_process_queue():
        await instance.connect_if_needed()

    @callback
    def _async_discovered_device(service_info: bluetooth.BluetoothServiceInfoBleak, change: bluetooth.BluetoothChange) -> None:
        """Subscribe to bluetooth changes."""
        LOGGER.debug("New service_info: %s", service_info)
        hass.loop.create_task(_connect_and_process_queue())

    entry.async_on_unload(
        bluetooth.async_register_callback(
            hass,
            _async_discovered_device,
            BluetoothCallbackMatcher({ADDRESS: mac}),
            bluetooth.BluetoothScanningMode.PASSIVE
        )
    )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        instance = hass.data[DOMAIN][entry.entry_id]
        await instance.disconnect()
    return unload_ok

async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    instance = hass.data[DOMAIN][entry.entry_id]
    if entry.title != instance.name:
        await hass.config_entries.async_reload(entry.entry_id)