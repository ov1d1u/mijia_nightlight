# Mijia Nightlight Integration for Home Assistant

[![GitHub release](https://img.shields.io/github/v/release/ov1d1u/mijia_nightlight)](https://github.com/ov1d1u/mijia_nightlight/releases)
[![License](https://img.shields.io/github/license/ov1d1u/mijia_nightlight)](https://github.com/ov1d1u/mijia_nightlight/blob/main/LICENSE)

Mijia Nightlight is a Home Assistant (HA) integration to control the Xiaomi Motion Activated Night Light 2 over Bluetooth Low Energy (BLE). This integration offers functionalities such as turning the light on or off, adjusting brightness, setting the duration, and modifying ambient light levels.

⚠️ **Note**: This is the initial release. Please be aware that it may contain bugs and limited features. Contributions and bug reports are welcome!

## Features

- Turn the night light on or off.
- Adjust the brightness of the light.
- Set the operation duration before the light turns off automatically.
- Change the ambient light sensitivity levels to dynamically control light activation.

## Installation

You can install this integration either manually or by using [Home Assistant Community Store (HACS)](https://hacs.xyz/).

### Manual Installation

1. Clone or download the repository:
   ```bash
   git clone https://github.com/ov1d1u/mijia_nightlight.git
   ```
   
2. Copy the `mijia_nightlight` directory from the repository to your Home Assistant `custom_components` directory:
   ```bash
   cp -r mijia_nightlight/custom_components/mijia_nightlight /config/custom_components/
   ```
   
3. Restart Home Assistant.

### HACS Installation

1. Ensure you have HACS installed. If not, follow the [HACS installation instructions](https://hacs.xyz/docs/installation/installation/).
   
2. Go to "HACS" in the Home Assistant sidebar.

3. Click the "Integration" tab.

4. Click the "+" button in the bottom right and search for "Mijia Nightlight".

5. Select the integration and click "Install".

6. Restart Home Assistant.

## Usage

Once configured, the Xiaomi Night Light devices will show up in your Home Assistant interface. You can use Home Assistant's automation and scripting features to control your night lights based on various conditions and triggers available in Home Assistant.

## Issues and Contributions

Since this is an initial release, there might be bugs or missing features. Please report any issues or bugs via the [GitHub issues page](https://github.com/ov1d1u/mijia_nightlight/issues). Contributions and feature requests are welcome via [Pull Requests](https://github.com/ov1d1u/mijia_nightlight/pulls).

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/ov1d1u/mijia_nightlight/blob/main/LICENSE) file for more details.

## Acknowledgements

- Yeelight xiaomi mesh light bulb auth sequence dump (@kabbi): https://gist.github.com/kabbi/32658d7d3a086cd47d877882933a9908
- TelinkMiFlasher (@pvvx): https://github.com/pvvx/pvvx.github.io/
- This blog post from Wankko Ree's Blog: https://wkr.moe/study/845.html
- Home Assistant community for their ongoing support and contributions!
