from abc import abstractmethod

class Message:
    @abstractmethod
    def get_bytes(self) -> bytes:
        pass


class OnOffMessage(Message):
    def __init__(self, is_on: bool):
        self.is_on = is_on

    def get_bytes(self) -> bytes:
        return bytes.fromhex("030203" + ("01" if self.is_on else "00"))


class BrightnessMessage(Message):
    def __init__(self, brightness: int):
        self.brightness = brightness

    def get_bytes(self) -> bytes:
        return bytes.fromhex(f"030202{self.brightness:02x}")


class DurationMessage(Message):
    def __init__(self, duration: int):
        self.duration = duration

    def get_bytes(self) -> bytes:
        return bytes.fromhex(f"030204{self.duration:02x}")


class AmbientLimitMessage(Message):
    def __init__(self, limit: int):
        self.limit = limit

    def get_bytes(self) -> bytes:
        return bytes.fromhex(f"030208{self.limit:02x}")


class GetConfigurationMessage(Message):
    def get_bytes(self) -> bytes:
        return bytes.fromhex("06010102030408")