from typing import Any
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_MAC
from homeassistant.data_entry_flow import FlowResult
from homeassistant.core import callback
from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info
)
from homeassistant.helpers.device_registry import format_mac
from .mijia import DeviceData
from .const import DOMAIN, CONF_MI_TOKEN
import logging

LOGGER = logging.getLogger(__name__)

MANUAL_MAC = "manual"

class YourIntegrationConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self):
        self.mac = None
        self.mi_token = None
        self._instance = None
        self._discovered_devices = []

    async def async_step_preparation(self, user_input=None):
        if user_input is not None:
            return await self.async_step_discovery()

        return self.async_show_form(
            step_id="preparation",
            description_placeholders={
                "instruction": "Please move in front of the device to make the device discoverable.",
            },
            data_schema=vol.Schema({}),
            errors={},
        )

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> FlowResult:
        """Handle the bluetooth discovery step."""
        LOGGER.debug("Discovered bluetooth devices, step bluetooth, : %s , %s", discovery_info.address, discovery_info.name)
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        device = DeviceData(self.hass, discovery_info)
        if device.is_supported:
            self._discovered_devices.append(device)
            return await self.async_step_bluetooth_confirm()
        else:
            return self.async_abort(reason="not_supported")

    async def async_step_bluetooth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Confirm discovery."""
        LOGGER.debug("Discovered bluetooth devices, step bluetooth confirm, : %s", user_input)
        self._set_confirm_only()
        return await self.async_step_user()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the user step to pick discovered device."""
        if user_input is not None:
            if user_input[CONF_MAC] == MANUAL_MAC:
                return await self.async_step_manual()
            self.mac = user_input[CONF_MAC]
            self.mi_token = user_input[CONF_MI_TOKEN]
            await self.async_set_unique_id(self.mac, raise_on_progress=False)
            self._abort_if_unique_id_configured()
            return await self.async_step_validate()

        current_addresses = self._async_current_ids()
        for discovery_info in async_discovered_service_info(self.hass):
            self.mac = discovery_info.address
            if self.mac in current_addresses:
                LOGGER.debug("Device %s in current_addresses", (self.mac))
                continue
            if (device for device in self._discovered_devices if device.address == self.mac) != ([]):
                #LOGGER.debug("Device with address %s in discovered_devices", self.mac)
                continue
            device = DeviceData(self.hass, discovery_info)
            if device.is_supported:
                self._discovered_devices.append(device)

        if not self._discovered_devices:
            return await self.async_step_manual()

        for device in self._discovered_devices:
            LOGGER.debug("Discovered supported devices: %s - %s - %s", device.name, device.address, device.rssi)

        mac_dict = { dev.address: dev.name for dev in self._discovered_devices }
        mac_dict[MANUAL_MAC] = "Manually add a MAC address"
        return self.async_show_form(
            step_id="user", data_schema=vol.Schema(
                {
                    vol.Required(CONF_MAC): vol.In(mac_dict),
                    vol.Required(CONF_MI_TOKEN): str
                }
            ),
            errors={})

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the user step to pick discovered device."""
        if user_input is not None:
            if user_input[CONF_MAC] == MANUAL_MAC:
                return await self.async_step_manual()
            self.mac = user_input[CONF_MAC]
            self.mi_token = user_input[CONF_MI_TOKEN]
            await self.async_set_unique_id(self.mac, raise_on_progress=False)
            self._abort_if_unique_id_configured()
            return await self.async_step_validate()

        current_addresses = self._async_current_ids()
        for discovery_info in async_discovered_service_info(self.hass):
            self.mac = discovery_info.address
            if self.mac in current_addresses:
                LOGGER.debug("Device %s in current_addresses", (self.mac))
                continue
            if (device for device in self._discovered_devices if device.address == self.mac) != ([]):
                #LOGGER.debug("Device with address %s in discovered_devices", self.mac)
                continue
            device = DeviceData(self.hass, discovery_info)
            if device.is_supported:
                self._discovered_devices.append(device)

        if not self._discovered_devices:
            return await self.async_step_manual()

        for device in self._discovered_devices:
            LOGGER.debug("Discovered supported devices: %s - %s - %s", device.name, device.address, device.rssi)

        mac_dict = { dev.address: dev.name for dev in self._discovered_devices }
        mac_dict[MANUAL_MAC] = "Manually add a MAC address"
        return self.async_show_form(
            step_id="user", data_schema=vol.Schema(
                {
                    vol.Required(CONF_MAC): vol.In(mac_dict),
                    vol.Required(CONF_MI_TOKEN): str
                }
            ),
            errors={})

    async def async_step_manual(self, user_input: "dict[str, Any] | None" = None):
        if user_input is not None:
            self.mac = user_input[CONF_MAC]
            self.mi_token = user_input[CONF_MI_TOKEN]
            await self.async_set_unique_id(format_mac(self.mac))
            return await self.async_step_validate()

        return self.async_show_form(
            step_id="manual", data_schema=vol.Schema(
                {
                    vol.Required(CONF_MAC): str,
                    vol.Required(CONF_MI_TOKEN): str
                }
            ), errors={})

    async def async_step_validate(self, user_input: "dict[str, Any] | None" = None):
        if user_input is not None:
            if "flicker" in user_input:
                if user_input["flicker"]:
                    return self.async_create_entry(title=self.mac, data={CONF_MAC: self.mac, CONF_MI_TOKEN: self.mi_token})
                return self.async_abort(reason="cannot_validate")

            if "retry" in user_input and not user_input["retry"]:
                return self.async_abort(reason="cannot_connect")

        error = await self.authenticate()

        if error:
            return self.async_show_form(
                step_id="validate", data_schema=vol.Schema(
                    {
                        vol.Required("retry"): bool
                    }
                ), errors={"base": "connect"})

        return self.async_show_form(
            step_id="validate", data_schema=vol.Schema(
                {
                    vol.Required("flicker"): bool
                }
            ), errors={})

    async def authenticate(self):
        return