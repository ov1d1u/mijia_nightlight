"""The Xiaomi Motion Activated Night Light 2 integration."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform, CONF_MAC
from homeassistant.core import HomeAssistant

from .const import DOMAIN, CONF_MI_TOKEN

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.NUMBER, Platform.SENSOR]

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Xiaomi Motion Activated Night Light 2 from a config entry."""

    mac = entry.options.get(CONF_MAC, None) or entry.data.get(CONF_MAC, None)
    mi_token = entry.options.get(CONF_MI_TOKEN, None) or entry.data.get(CONF_MI_TOKEN, None)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


# TODO Update entry annotation
async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
