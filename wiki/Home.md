![Tesla Battery Plugin Banner](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/wiki/banner.png)

# Tesla Battery Plugin for Indigo Domo

Connect your Tesla Powerwall to [Indigo Domo](https://www.indigodomo.com) for live monitoring, automation, and control — all from your local network and optionally via the Tesla cloud API.

---

## Features at a Glance

| | Feature | Description |
|---|---|---|
| 🔋 | **Battery Charge & State** | Real-time charge percentage, charging / discharging / idle state |
| 🛡️ | **Backup Reserve** | Read and set your backup reserve percentage |
| ⚡ | **Power Flow** | Live watts for solar, battery, grid, and home load |
| 📡 | **Live Monitoring** | Local gateway polling — no cloud dependency for data |
| 💰 | **Tariff Awareness** | Reads your Tesla TOU tariff plan and tracks the current rate period |
| 🔔 | **Event Updates** | Detects grid loss / restoration, battery state transitions, grid faults |
| 📊 | **Indigo States** | Rich device states usable in triggers, scripts, and control pages |
| 🤖 | **Automation** | Full trigger support — act on grid loss, battery changes, solar export |

---

## Powerwall Device Images

500+ images included for use in Indigo control pages. The `batteryState_combined` state drives image selection automatically.

| Charging 50% | Idle 50% | Discharging 75% |
|:---:|:---:|:---:|
| ![charging](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/Combined/powerwall_comb%2Bcharging_50.png) | ![idle](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/Combined/powerwall_comb%2Bidle_50.png) | ![discharging](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/Combined/powerwall_comb%2Bdischarging_75.png) |

| 25% | 50% | 75% | 100% |
|:---:|:---:|:---:|:---:|
| ![25](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/powerwall%2B25.png) | ![50](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/powerwall%2B50.png) | ![75](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/powerwall%2B75.png) | ![100](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/powerwall%2B100.png) |

See [Control Pages & Images](Control-Pages-and-Images) for full setup instructions.

---

## Quick Navigation

| Page | What's inside |
|---|---|
| [Installation](Installation) | Requirements, download, first-run setup |
| [Configuration](Configuration) | Every Plugin Config field explained |
| [Devices](Devices) | All four devices and their states |
| [Actions](Actions) | Set operational mode, change backup reserve |
| [Triggers & Automation](Triggers-and-Automation) | All trigger events with example use cases |
| [Control Pages & Images](Control-Pages-and-Images) | Using Powerwall images in Indigo control pages |
| [Changelog](Changelog) | Full version history |

---

## Requirements

- **Tesla Powerwall** with Gateway (Gen 1 or Gen 2)
- **Indigo Domo** 2022.1 or later (tested through 2025.2)
- **Python 3.10+** (bundled with modern Indigo)
- The Gateway must be on the same local network as your Indigo Mac
- A static IP address assigned to the Gateway (via your router's DHCP reservation)
- *(Optional)* Tesla account email + Refresh Token for online features (backup reserve control, remaining time, tariff data)

---

## Architecture Overview

The plugin uses **two independent communication paths**:

```
┌─────────────────────────────────────────────────────────┐
│  LOCAL PATH  (always on, no cloud required)             │
│  Indigo → HTTPS → Powerwall Gateway (192.168.x.x)      │
│  • Power flow data  • Battery %  • Grid status          │
│  • Polling every 10–60 seconds                          │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  ONLINE PATH  (optional, requires Tesla account)        │
│  Indigo → HTTPS → owner-api.teslamotors.com             │
│  • Backup reserve %  • Battery mode  • Time remaining   │
│  • Tariff rate  • Storm mode  • Battery count           │
└─────────────────────────────────────────────────────────┘
```

> The local path provides all real-time monitoring. The online path is only needed if you want to **control** the battery (change mode / reserve) or read online-only states.

---

## Plugin ID

`com.GlennNZ.indigoplugin.TeslaBattery`

---

*Developed by GlennNZ — [GitHub](https://github.com/Ghawken/TeslaBatteryPlugin/) — [Indigo Forums](https://forums.indigodomo.com)*
