import asyncio
import secrets
import hashlib
import hmac
import logging
from Crypto.Cipher import AES
from homeassistant.components import bluetooth
from bleak import BleakClient
from bleak.exc import BleakDeviceNotFoundError

from .mjyd2sconfiguration import MJYD2SConfiguration
from .eventbus import EventBus
from .exc import AuthenticationError, ResponseError
from .msg import (
    OnOffMessage,
    BrightnessMessage,
    DurationMessage,
    AmbientLimitMessage,
    GetConfigurationMessage
)
from .queue import OutQueue
from ..const import (
    DEVICE_CONNECTED_EVENT,
    DEVICE_DISCONNECTED_EVENT,
    DEVICE_UPDATED_EVENT
)

LOGGER = logging.getLogger(__name__)

CHAR_10_UUID = "00000010-0000-1000-8000-00805f9b34fb"
CHAR_19_UUID = "00000019-0000-1000-8000-00805f9b34fb"

CHAR_TX_UUID = "00000101-0065-6c62-2e74-6f696d2e696d"
CHAR_RX_UUID = "00000102-0065-6c62-2e74-6f696d2e696d"

DISCOVERY_TIMEOUT = 30.0
REPLY_TIMEOUT = 30.0
DISCONNECT_DELAY = 60.0


class MJYD2S:
    client = None
    mac = None
    hass = None

    eventbus = EventBus()

    _queue_in = asyncio.Queue()
    _queue_out = OutQueue()
    _connect_lock = asyncio.Lock()
    _disconnect_task = None
    _configuration = None

    def __init__(self, hass, mac, mi_token, use_out_queue=False):
        self.hass = hass
        self.mac = mac
        self.mi_token = mi_token
        self.use_out_queue = use_out_queue
        self.prepare_for_reuse()

    @property
    def configuration(self):
        return self._configuration

    @configuration.setter
    def configuration(self, configuration):
        self._configuration = configuration
        self.eventbus.send(DEVICE_UPDATED_EVENT, configuration)

    def prepare_for_reuse(self):
        self.mi_random_key = secrets.token_bytes(16)
        self.mi_random_key_recv = None
        self.derived_key = None
        self._msg_count = 0
        self._clear_in_queue()

    async def connect(self) -> bool:
        async with self._connect_lock:
            if self.client and self.is_connected:
                return True

            device = bluetooth.async_ble_device_from_address(self.hass, self.mac, connectable=True)
            if not device:
                return False

            self.prepare_for_reuse()
            self.client = BleakClient(device)
            try:
                await self.client.connect()
            except:
                return False

            await asyncio.sleep(2.0)  # give some time for service discovery

            if self.is_authenticated:
                return True

            await self.client.start_notify(CHAR_19_UUID, self._notification_handler)
            await self.client.start_notify(CHAR_10_UUID, self._notification_handler)

            await self._write(CHAR_10_UUID, bytes.fromhex("a4"))
            response = await self._get_response(decrypt=False)
            self._assert_response(bytes.fromhex("0000040006f2"), response)

            await self._write(CHAR_19_UUID, bytes.fromhex("0000050006f2"))
            mtu_response = await self._get_response(decrypt=False)
            mtu_response[2] = mtu_response[2] + 1
            await asyncio.sleep(1)
            await self._write(CHAR_19_UUID, mtu_response)

            # For some reason we have to wait a bit here,
            # otherwise the device will no longer respond
            await asyncio.sleep(5)

            await self._write(CHAR_10_UUID, bytes.fromhex("24000000"))
            await asyncio.sleep(1)
            await self._write(CHAR_19_UUID, bytes.fromhex("0000000b0100"))
            response = await self._get_response(decrypt=False)
            self._assert_response(bytes.fromhex("00000101"), response)

            await self._write(CHAR_19_UUID, bytes.fromhex("0100") + self.mi_random_key)
            response = await self._get_response(decrypt=False)
            self._assert_response(bytes.fromhex("00000100"), response)

            key_msg = await self._get_response(decrypt=False)
            self.mi_random_key_recv = key_msg[4:]

            self.derived_key = self._hkdf(
                bytes.fromhex(self.mi_token),
                64,
                self.mi_random_key + self.mi_random_key_recv,
                b"mible-login-info"
            )

            await self._write(CHAR_19_UUID, bytes.fromhex("00000300"))
            response = await self._get_response(decrypt=False)
            mi_device_info_recv = response[4:]

            expected_mi_device_info = hmac.new(
                self.derived_key[0:16],
                self.mi_random_key_recv + self.mi_random_key,
                hashlib.sha256
            ).digest()

            if response == bytes.fromhex("0000000c0200"):
                await self._write(CHAR_19_UUID, bytes.fromhex("00000101"))
                response = await self._get_response(decrypt=False)
                mi_device_info_recv_part_1 = response[2:]
                response = await self._get_response(decrypt=False)
                mi_device_info_recv_part_2 = response[2:]
                mi_device_info_recv = mi_device_info_recv_part_1 + mi_device_info_recv_part_2

            if mi_device_info_recv != expected_mi_device_info:
                raise AuthenticationError(f"Fatal error: device info mismatch. Received {mi_device_info_recv.hex()}, expected {expected_mi_device_info.hex()}")

            await self._write(CHAR_19_UUID, bytes.fromhex("00000300"))
            await self._write(CHAR_19_UUID, bytes.fromhex("0000000a0100"))

            response = await self._get_response(decrypt=False)
            self._assert_response(bytes.fromhex("00000101"), response)

            mi_device_info_send = hmac.new(
                self.derived_key[16:32],
                self.mi_random_key + self.mi_random_key_recv,
                hashlib.sha256
            ).digest()
            await self._write(CHAR_19_UUID, bytes.fromhex("0100") + mi_device_info_send)

            response = await self._get_response(decrypt=False)
            self._assert_response(bytes.fromhex("00000100"), response)

            response = await self._get_response(decrypt=False)
            self._assert_response(bytes.fromhex("21000000"), response)

            await self.client.stop_notify(CHAR_19_UUID)
            await self.client.stop_notify(CHAR_10_UUID)
            await self.client.start_notify(CHAR_RX_UUID, self._notification_handler)

            await self.get_configuration()
            self.eventbus.send(DEVICE_CONNECTED_EVENT)

            await self._process_out_queue()

            return True

    async def connect_if_needed(self):
        if self.is_connected and self.is_authenticated:
            return

        if self._configuration is None:
            LOGGER.debug("Connecting because configuration is None")
        elif self._configuration.is_expired:
            LOGGER.debug("Connecting because configuration is expired")
        elif not self._queue_out.empty():
            LOGGER.debug("Connecting because out queue is not empty")

        if self._configuration is None or \
            self._configuration.is_expired or \
            not self._queue_out.empty():
            await self.connect()

    async def disconnect(self):
        if not self.client:
            return False

        if not self.is_connected:
            return False

        try:
            await self.client.stop_notify(CHAR_19_UUID)
            await self.client.stop_notify(CHAR_10_UUID)
            await self.client.stop_notify(CHAR_RX_UUID)
        except:
            pass

        await self.client.disconnect()
        self.eventbus.send(DEVICE_DISCONNECTED_EVENT)

    async def delayed_disconnect(self):
        if not self.client.is_connected:
            return

        try:
            await asyncio.sleep(DISCONNECT_DELAY)
            await self.disconnect()
            if self._disconnect_task:
                self._disconnect_task.cancel()
                self._disconnect_task = None
            LOGGER.debug(f"Disconnected from {self.mac}")
        except Exception as e:
            LOGGER.debug(f"Failed to disconnect. Error: {e}")

    async def get_configuration(self) -> MJYD2SConfiguration | None:
        await self._send_message(GetConfigurationMessage())

    async def turn_on(self, refresh_configuration: bool = True):
        await self._send_message(OnOffMessage(True))
        if refresh_configuration:
            await self.get_configuration()

    async def turn_off(self, refresh_configuration: bool = True):
        await self._send_message(OnOffMessage(False))
        if refresh_configuration:
            await self.get_configuration()

    async def set_brightness(self, brightness: int, refresh_configuration: bool = True):
        await self._send_message(BrightnessMessage(brightness))
        if refresh_configuration:
            await self.get_configuration()

    async def set_duration(self, timeout: int, refresh_configuration: bool = True):
        await self._send_message(DurationMessage(timeout))
        if refresh_configuration:
            await self.get_configuration()

    async def set_ambient_limit(self, limit: int, refresh_configuration: bool = True):
        await self._send_message(AmbientLimitMessage(limit))
        if refresh_configuration:
            await self.get_configuration()

    @property
    def is_connected(self):
        return self.client and self.client.is_connected

    @property
    def is_authenticated(self):
        return self.mi_token is not None and \
            self.derived_key is not None and \
            self.mi_random_key_recv is not None and \
            self.mi_random_key is not None

    async def _ensure_authenticated(self):
        if not self.is_connected or not self.is_authenticated:
            await self.connect()

    def _assert_response(self, expected, response):
        if response != expected:
            raise ResponseError(f"Invalid response received; received {response.hex()}, expected {expected.hex()}")

    async def _send_message(self, msg):
        if self.is_connected and self.is_authenticated:
            await self._write_message(msg)
        elif self.use_out_queue:
            await self._queue_out.put(msg)
            LOGGER.debug(f"Not connected, put message on out queue (queue size: {self._queue_out.qsize()})")

    async def _write_message(self, msg):
        hex_msg_count = self._msg_count.to_bytes(2, byteorder='little').hex()
        msg_bytes = bytes.fromhex(hex_msg_count) + self._encrypt_message(msg.get_bytes())
        self._msg_count += 1
        await self._write(CHAR_TX_UUID, msg_bytes)

    async def _wait_response(self, expected_msg_count):
        if expected_msg_count is not None:
            while True:
                in_msg = await self._queue_in.get()
                in_msg_count = int.from_bytes(in_msg[0:2], byteorder='little')

                if in_msg_count == expected_msg_count:
                    return in_msg
        else:
            return await self._queue_in.get()

    async def _get_response(self, expected_msg_count: int|None = None, decrypt: bool = True) -> bytes | None:
        try:
            response = await asyncio.wait_for(self._wait_response(expected_msg_count), timeout=REPLY_TIMEOUT)

            if decrypt:
                return self._decrypt_message(response)
            else:
                return response
        except asyncio.TimeoutError:
            return None

    async def _write(self, charac, data):
        LOGGER.debug(f">> {data.hex()}")
        result = await self.client.write_gatt_char(charac, data)
        loop = asyncio.get_running_loop()

        if self._disconnect_task is not None:
            self._disconnect_task.cancel()
        self._disconnect_task = loop.create_task(self.delayed_disconnect())

        return result

    def _clear_in_queue(self):
        while not self._queue_in.empty():
            self._queue_in.get_nowait()

    async def _process_out_queue(self):
        while not self._queue_out.empty():
            msg = await self._queue_out.get()
            await self._write_message(msg)

    async def _notification_handler(self, sender, data):
        if sender.uuid.lower() == CHAR_19_UUID.lower() or \
            sender.uuid.lower() == CHAR_10_UUID.lower():
            LOGGER.debug(f"<< {data.hex()}")
            self._queue_in.put_nowait(data)
        elif sender.uuid.lower() == CHAR_RX_UUID.lower():
            msg_count = int.from_bytes(data[0:2], byteorder='little')
            in_message = self._decrypt_message(msg_count, data)
            LOGGER.debug(f"<< {in_message.hex()}")
            if in_message[0:2] == bytes.fromhex("0703"):
                self.configuration = MJYD2SConfiguration(in_message)
                return self.configuration

    def _hkdf_extract(self, salt, input_key, hash_func):
        return hmac.new(salt, input_key, hash_func).digest()

    def _hkdf_expand(self, prk, info, length, hash_func):
        block = b""
        output = b""
        counter = 1
        while len(output) < length:
            block = hmac.new(prk, block + info + bytes([counter]), hash_func).digest()
            output += block
            counter += 1
        return output[:length]

    def _hkdf(self, input_key, length, salt, info, hash_func=hashlib.sha256):
        prk = self._hkdf_extract(salt, input_key, hash_func)
        return self._hkdf_expand(prk, info, length, hash_func)

    def _encrypt_message(self, msg):
        nonce = self._compute_enc_nonce()
        cipher = AES.new(
            self.derived_key[16:32],
            AES.MODE_CCM,
            nonce=nonce,
            mac_len=4
        )
        ciphertext, tag = cipher.encrypt_and_digest(msg)
        return ciphertext + tag

    def _decrypt_message(self, msg_count, msg):
        nonce = self._compute_dec_nonce(msg_count)
        cipher = AES.new(
            self.derived_key[0:16],
            AES.MODE_CCM,
            nonce=nonce,
            mac_len=4
        )
        chipertext = msg[2:len(msg) - 4]
        tag = msg[len(msg) - 4:]
        return cipher.decrypt_and_verify(chipertext, tag)

    def _compute_enc_nonce(self):
        nonce = 12 * [0]
        nonce[:4] = self.derived_key[36:40]
        nonce[8: 10] = self._msg_count.to_bytes(2, byteorder='little')
        nonce[10:12] = [0, 0]
        return bytes(nonce)

    def _compute_dec_nonce(self, msg_count):
        nonce = 12 * [0]
        nonce[:4] = self.derived_key[32:36]
        nonce[8:10] = msg_count.to_bytes(2, byteorder='little')
        nonce[10:12] = [0, 0]
        return bytes(nonce)

