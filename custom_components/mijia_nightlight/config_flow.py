import logging
import voluptuous as vol
from typing import Any
from homeassistant import config_entries
from homeassistant.const import CONF_MAC
from homeassistant.data_entry_flow import FlowResult
from homeassistant.components.bluetooth import (
    async_discovered_service_info,
    async_ble_device_from_address
)
from homeassistant.helpers.device_registry import format_mac
from .mjyd2s import MJYD2S
from .mjyd2sdevicedata import MJYD2SDeviceData
from .const import DOMAIN, CONF_MI_TOKEN

LOGGER = logging.getLogger(__name__)

MANUAL_MAC = "manual"

class MijiaNighlightConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self):
        self.name = "MiJia Nightlight 2"
        self.mac = None
        self.mi_token = None
        self._instance = None
        self._discovered_devices = []

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the user step to pick discovered device."""
        if user_input is not None:
            return await self.async_step_scan_results()

        return self.async_show_form(
            step_id='user',
            data_schema=vol.Schema({})
        )
    
    async def async_step_scan_results(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the user step to pick discovered device."""
        if user_input is not None:
            if user_input[CONF_MAC] == MANUAL_MAC:
                return await self.async_step_manual_mac()

            self.mac = user_input[CONF_MAC]
            await self.async_set_unique_id(format_mac(self.mac), raise_on_progress=False)
            self._abort_if_unique_id_configured()
            return await self.async_step_token()

        discovered_devices = []
        for device in async_discovered_service_info(self.hass):
            device_data = MJYD2SDeviceData(self.hass, device)
            if device_data.is_supported:
                discovered_devices.append(device_data)

        device_options = {dev.address: f"{dev.name} ({dev.address})" for dev in discovered_devices}
        device_options[MANUAL_MAC] = "Enter MAC address manually"

        return self.async_show_form(
            step_id='scan_results',
            data_schema=vol.Schema({
                vol.Required(CONF_MAC): vol.In(device_options)
            }),
            description_placeholders={
                "description": "Please select a device to configure"
            }
        )

    async def async_step_manual_mac(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the user step to pick discovered device."""
        if user_input is not None:
            if user_input[CONF_MAC] == MANUAL_MAC:
                return await self.async_step_manual()
            self.mac = user_input[CONF_MAC]
            self.mi_token = user_input[CONF_MI_TOKEN]
            await self.async_set_unique_id(format_mac(self.mac), raise_on_progress=False)
            self._abort_if_unique_id_configured()
            return await self.async_step_validate()

        return self.async_show_form(
            step_id="manual_mac",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_MAC): str,
                    vol.Required(CONF_MI_TOKEN): str
                }
            ),
            errors={})

    async def async_step_token(self, user_input: "dict[str, Any] | None" = None):        
        if user_input is not None:
            self.mi_token = user_input[CONF_MI_TOKEN]
            return await self.async_step_validate()

        return self.async_show_form(
            step_id="token", data_schema=vol.Schema(
                {
                    vol.Required(CONF_MI_TOKEN): str
                }
            ), errors={})
    
    async def async_step_validate(self, user_input: "dict[str, Any] | None" = None):
        if user_input is not None:
            return self.async_create_entry(title=self.name, data={CONF_MAC: self.mac, "name": self.name})
        
        try:
            error = await self.validate_device()
        except Exception as e:
            error = str(e)

        if error:
            return self.async_show_form(
                step_id="validate", data_schema=vol.Schema(
                    {
                        vol.Required("retry"): bool
                    }
                ), errors={"base": error})

        return self.async_create_entry(title=self.name, data={CONF_MAC: self.mac, CONF_MI_TOKEN: self.mi_token, "name": self.name})
    
    async def validate_device(self):
        mijia = MJYD2S(self.hass, self.mac, self.mi_token)
        assert await mijia.connect()
        assert await mijia.authenticate()
        await mijia.get_configuration()
        await mijia.disconnect()

        return None