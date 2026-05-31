![Tesla Battery Plugin](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/wiki/banner.png)

# Tesla Battery Plugin for Indigo Domo

Connect your Tesla Powerwall to [Indigo Domo](https://www.indigodomo.com) for live monitoring, automation, and control — entirely from your local network, with optional Tesla cloud features.

[![Version](https://img.shields.io/badge/version-1.0.27-brightgreen)](https://github.com/Ghawken/TeslaBatteryPlugin/releases)
[![Indigo](https://img.shields.io/badge/Indigo-2022.1%2B-blue)](https://www.indigodomo.com)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org)

---

## Features

| | |
|---|---|
| 🔋 Real-time charge percentage and battery state | ⚡ Live power flow — solar, grid, home, battery |
| 🛡️ Read and set backup reserve percentage | 📡 Local network polling — no cloud needed for monitoring |
| 💰 TOU tariff tracking (current rate period) | 🔔 Triggers on grid loss, restoration, faults, battery state |
| 📊 Rich Indigo device states for triggers & scripts | 🤖 Control battery mode and reserve via Action Groups |

---

## Quick Start

1. **[Download the latest release](https://github.com/Ghawken/TeslaBatteryPlugin/releases)** and double-click to install
2. Assign a **static IP** to your Powerwall Gateway in your router
3. Open **Plugins → Tesla Battery → Configure** — enter the Gateway IP, your Tesla email, and local password
4. Click **Check Connection**, then **Generate Tesla Devices**
5. *(Optional)* Enable **Allow Online Communication** and add a [Refresh Token](https://github.com/Ghawken/TeslaBatteryPlugin/wiki/Configuration#online-access-refresh-token) for remote control and extended states

Full setup guide → **[Installation wiki page](https://github.com/Ghawken/TeslaBatteryPlugin/wiki/Installation)**

---

## Documentation

All documentation is in the **[Wiki](https://github.com/Ghawken/TeslaBatteryPlugin/wiki)**:

| | |
|---|---|
| 📖 [Installation](https://github.com/Ghawken/TeslaBatteryPlugin/wiki/Installation) | Step-by-step setup, static IP, refresh token |
| ⚙️ [Configuration](https://github.com/Ghawken/TeslaBatteryPlugin/wiki/Configuration) | Every Plugin Config field explained |
| 📟 [Devices & States](https://github.com/Ghawken/TeslaBatteryPlugin/wiki/Devices) | All four devices and their full state lists |
| 🎮 [Actions](https://github.com/Ghawken/TeslaBatteryPlugin/wiki/Actions) | Set operational mode, change backup reserve |
| ⚡ [Triggers & Automation](https://github.com/Ghawken/TeslaBatteryPlugin/wiki/Triggers-and-Automation) | Grid loss, battery events, example automations |
| 🖼️ [Control Pages & Images](https://github.com/Ghawken/TeslaBatteryPlugin/wiki/Control-Pages-and-Images) | Using Powerwall images in control pages |
| 📋 [Changelog](https://github.com/Ghawken/TeslaBatteryPlugin/wiki/Changelog) | Full version history |

---

## What Gets Created

After running **Generate Devices**, four devices appear in the **Tesla Battery Gateway** folder:

| Device | Source | Key states |
|---|---|---|
| **Tesla Site Info** | Local + Online | Site name, grid code, battery mode, reserve %, tariff rate |
| **Tesla Battery** | Local + Online | Charge %, time remaining, storm mode, firmware version |
| **Tesla Grid Status** | Local | Connected/islanded, grid loss/restore timestamps, faults |
| **Tesla Meters** | Local | Solar W, Grid W, Home W, Battery W, solar/battery/grid boolean states |

---

## Powerwall Images

The plugin includes 500+ images for use in Indigo control pages — charge level images (1–100%), combined state + charge images for all three states (charging / idle / discharging), and flow indicator icons.

| Charging 50% | Idle 50% | Discharging 75% |
|:---:|:---:|:---:|
| ![charging](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/Combined/powerwall_comb%2Bcharging_50.png) | ![idle](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/Combined/powerwall_comb%2Bidle_50.png) | ![discharging](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/Combined/powerwall_comb%2Bdischarging_75.png) |

The `batteryState_combined` device state (e.g. `charging_73`) maps directly to these filenames. See the [Control Pages wiki page](https://github.com/Ghawken/TeslaBatteryPlugin/wiki/Control-Pages-and-Images) for setup instructions.

---

## Requirements

- Tesla Powerwall with Gateway on your local network
- Indigo Domo 2022.1 or later
- Python 3.10+ (bundled with Indigo)
- Static/reserved IP address for the Gateway
- *(Online features)* Tesla account + Refresh Token

---

## Support

- **[Wiki](https://github.com/Ghawken/TeslaBatteryPlugin/wiki)** — full documentation
- **[Issues](https://github.com/Ghawken/TeslaBatteryPlugin/issues)** — bug reports and feature requests
- **[Indigo Forums](https://forums.indigodomo.com)** — community discussion

---

*Developed by Glenn Hawken · [MIT Licence](LICENSE)*
