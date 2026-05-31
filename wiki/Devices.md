![Tesla Battery Plugin](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/wiki/banner.png)

# Devices

The plugin creates four devices inside the **Tesla Battery Gateway** folder. They are generated automatically by clicking **Generate Tesla Devices** in Plugin Config.

---

## Tesla Site Info  `teslaSite`

Populated from the local gateway `/api/site_info` endpoint (every 10 minutes) and from the Tesla cloud API (every hour, online mode only).

**Display state:** `sitename`

### States

| State ID | Type | Source | Description |
|---|---|---|---|
| `deviceIsOnline` | Boolean | Local | True when the gateway is reachable |
| `deviceLastUpdated` | String | Local | Timestamp of last successful update |
| `sitename` | String | Local | Site name set in the Tesla app |
| `timezone` | String | Local | IANA timezone string (e.g. `Australia/Sydney`) |
| `nominalEnergy` | String | Local | System energy capacity in kWh |
| `nominalPower` | String | Local | System power rating in kW |
| `gridCode` | String | Local | Full grid code string |
| `gridVoltage` | String | Local | Grid voltage setting (V) |
| `gridFreq` | String | Local | Grid frequency setting (Hz) |
| `gridPhase` | String | Local | Phase setting (e.g. `Single`, `Split`) |
| `country` | String | Local | Country from grid code |
| `state` | String | Local | State/region from grid code |
| `region` | String | Local | Grid policy region |
| `utility` | String | Local | Utility provider name |
| `distributor` | String | Local | Distributor name |
| `frequency` | String | Local | Measured grid frequency |
| `batteryMode` | String | Online | Current operational mode (`autonomous`, `self_consumption`, `backup`) |
| `batteryReservePercentage` | Number | Online | Current backup reserve % |
| `stormMode` | Boolean | Online | Whether Storm Watch / Storm Mode is enabled |
| `batteryCount` | Number | Online | Number of Powerwall units |
| `version` | String | Online | Gateway firmware version |
| `current_tarriff_name` | String | Online | Current TOU period name (e.g. `Peak`, `Off-Peak`) |
| `current_tarriff_price` | String | Online | Current TOU rate (as returned by Tesla tariff API) |

---

## Tesla Battery  `teslaBattery`

Populated from the local gateway `/api/system_status/soe` endpoint (every 60 seconds) and from the Tesla cloud API for extended states.

**Display state:** `chargeCP`

<div align="center">

| 5% | 25% | 50% | 75% | 100% |
|:---:|:---:|:---:|:---:|:---:|
| ![5%](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/powerwall%2B5.png) | ![25%](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/powerwall%2B25.png) | ![50%](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/powerwall%2B50.png) | ![75%](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/powerwall%2B75.png) | ![100%](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/powerwall%2B100.png) |

*Battery charge level images (1–100 available)*

</div>

### States

| State ID | Type | Source | Description |
|---|---|---|---|
| `deviceIsOnline` | Boolean | Local | True when the gateway is reachable |
| `deviceLastUpdated` | String | Local | Timestamp of last successful update |
| `charge` | Number | Local | Battery charge as a float percentage (e.g. `73.4`) |
| `chargeCP` | Number | Local | Battery charge as integer — best for control page display |
| `batteryMode` | String | Online | Operational mode: `autonomous`, `self_consumption`, or `backup` |
| `batteryReservePercentage` | Number | Online | Backup reserve threshold (%) |
| `stormMode` | Boolean | Online | Storm Watch active |
| `batteryCount` | Number | Online | Number of Powerwall units |
| `version` | String | Online | Gateway firmware version |
| `battery_backtimeRemaining` | Number | Online | Estimated backup runtime in decimal hours |
| `battery_remainingTimeText` | String | Online | Human-readable remaining time (e.g. `4h 30m`) |

### Indigo Battery Level Image

The device icon automatically reflects charge level:

| Range | Indigo image |
|---|---|
| > 95% | `BatteryLevelHigh` |
| 76–95% | `BatteryLevel75` |
| 51–75% | `BatteryLevel50` |
| 26–50% | `BatteryLevel25` |
| ≤ 25% | `BatteryLevelLow` |

---

## Tesla Grid Status  `teslaGridStatus`

Populated from the local gateway `/api/system_status/grid_status` endpoint (every 10 seconds) and `/api/system_status/grid_faults` (every 2 minutes).

**Display state:** `gridConnected`

### States

| State ID | Type | Source | Description |
|---|---|---|---|
| `deviceIsOnline` | Boolean | Local | True when the gateway is reachable |
| `deviceLastUpdated` | String | Local | Timestamp of last successful update |
| `gridConnected` | Boolean | Local | `True` = grid up, `False` = islanded / outage |
| `gridStatus` | String | Local | Raw gateway value: `SystemGridConnected`, `SystemIslandedActive`, or `SystemIslandedReady` |
| `timeGridLoss` | String | Local | Timestamp when grid last went down |
| `timeGridUp` | String | Local | Timestamp when grid last came back |
| `gridFaults` | String | Local | JSON list of current fault objects (empty list `[]` = no faults) |

### Grid Status Values

| `gridStatus` | `gridConnected` | Meaning |
|---|---|---|
| `SystemGridConnected` | `True` | Normal operation, grid present |
| `SystemIslandedActive` | `False` | Grid is down, Powerwall is supplying home |
| `SystemIslandedReady` | `False` | Grid down, transitioning to island mode |

---

## Tesla Meters  `teslaMeters`

Populated from the local gateway `/api/meters/aggregates` endpoint (every 15 seconds). This is the richest real-time device.

**Display state:** `Home`

<div align="center">

| ![Solar](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Control%20Page%20Images/solar.png) | ![Grid](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Control%20Page%20Images/Grid.png) | ![Home](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Control%20Page%20Images/Home.png) | ![Battery](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Control%20Page%20Images/TeslaCP.png) |
|:---:|:---:|:---:|:---:|
| Solar | Grid | Home | Battery |

</div>

### Power States

| State ID | Type | Description |
|---|---|---|
| `Solar` | Number | Solar generation in Watts |
| `SolarkW` | Number | Solar generation in kW (1 decimal place) |
| `Grid` | Number | Grid import (+) / export (−) in Watts |
| `GridkW` | Number | Grid import/export in kW |
| `Home` | Number | Home consumption in Watts |
| `HomekW` | Number | Home consumption in kW |
| `Battery` | Number | Battery discharge (+) / charge (−) in Watts |
| `BatterykW` | Number | Battery discharge/charge in kW |

### Boolean & Derived States

| State ID | Type | Description | Threshold |
|---|---|---|---|
| `solarGenerating` | Boolean | Solar panels producing power | > 95 W |
| `gridUsage` | Boolean | Drawing power from the grid | > 250 W import |
| `sendingtoGrid` | Boolean | Exporting power to the grid | > 100 W export |
| `batteryCharging` | Boolean | Battery is being charged | > 100 W charge |
| `batteryDischarging` | Boolean | Battery is supplying power | > 150 W discharge |
| `batteryState` | String | Text state: `idle`, `charging`, or `discharging` | — |
| `batteryState_combined` | String | State + charge level, e.g. `charging_73` | — |
| `deviceIsOnline` | Boolean | Gateway reachable | — |
| `deviceStatus` | String | `Online` or `Offline` | — |
| `deviceLastUpdated` | String | Timestamp of last update | — |

### `batteryState_combined` Format

This state combines the battery activity state with the current charge percentage — ideal for using the Combined device images in control pages:

```
charging_73      →  battery is charging, 73% full
discharging_45   →  battery is discharging, 45% full
idle_88          →  battery is idle, 88% full
```

The number matches the `chargeCP` integer from the Tesla Battery device and corresponds directly to the 300 image files in `PowerwallImages/Device/Combined/`. See [Control Pages & Images](Control-Pages-and-Images) for how to wire this up.
