![Tesla Battery Plugin](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/wiki/banner.png)

# Control Pages & Images

The plugin ships with a large set of Powerwall images designed for Indigo control pages. They show the battery's charge level and activity state visually.

---

## Image Sets Overview

All images live in the `PowerwallImages/` folder of the plugin repository.

| Folder | Count | Image type | Use |
|---|---|---|---|
| `Device/` | 100 | `powerwall+{1–100}.png` | Charge level only (no state indicator) |
| `Device/Powerwall APNGs/` | 100 | `powerwall+{1–100}.png` | Animated PNG versions |
| `Device/Combined/` | 300 | `powerwall_comb+{state}_{pct}.png` | Charge level **+** activity state |
| `Device/Combined-small/` | 300 | `powerwall_comb_small+{state}_{pct}.png` | Smaller versions of combined |
| `Control Page Images/` | 4 | Named icons | Solar, Grid, Home, Battery icons |

---

## Charge Level Images

One image per percentage point, 1–100. The fill colour rises from the bottom as charge increases.

| 5% | 25% | 50% | 75% | 100% |
|:---:|:---:|:---:|:---:|:---:|
| ![5](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/powerwall%2B5.png) | ![25](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/powerwall%2B25.png) | ![50](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/powerwall%2B50.png) | ![75](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/powerwall%2B75.png) | ![100](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/powerwall%2B100.png) |

**Filename pattern:** `PowerwallImages/Device/powerwall+{N}.png`  
where `{N}` is the integer charge percentage (1–100).

**State to use:** `Tesla Battery → chargeCP` (integer, 1–100)

---

## Combined State + Charge Images

300 images covering all three battery states at every charge percentage.

| State | Charging (50%) | Idle (50%) | Discharging (75%) |
|:---:|:---:|:---:|:---:|
| | ![charging 50](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/Combined/powerwall_comb%2Bcharging_50.png) | ![idle 50](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/Combined/powerwall_comb%2Bidle_50.png) | ![discharging 75](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Device/Combined/powerwall_comb%2Bdischarging_75.png) |
| Visual | Green fill + upward arrow | Green fill, no animation | Red fill + downward arrow |

**Filename pattern:** `PowerwallImages/Device/Combined/powerwall_comb+{state}_{pct}.png`

| `{state}` | Meaning |
|---|---|
| `charging` | Battery is charging (green, animated arrow up) |
| `idle` | Battery is idle (green, no animation) |
| `discharging` | Battery is discharging (red, animated arrow down) |

**State to use:** `Tesla Meters → batteryState_combined`  
This state is already in the exact format needed — e.g. `charging_73` — matching the filename `powerwall_comb+charging_73.png`.

---

## Control Page Icons

Four circular icons for use alongside power readings:

| Image | Filename | Use |
|:---:|---|---|
| ![Solar](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Control%20Page%20Images/solar.png) | `solar.png` | Next to Solar Watts / kW label |
| ![Grid](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Control%20Page%20Images/Grid.png) | `Grid.png` | Next to Grid import/export label |
| ![Home](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Control%20Page%20Images/Home.png) | `Home.png` | Next to Home consumption label |
| ![Battery](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/Control%20Page%20Images/TeslaCP.png) | `TeslaCP.png` | Next to Battery Watts / kW label |

---

## Setting Up a Control Page

### Step 1 — Add the Powerwall image

1. Open your control page in Indigo
2. Add a **Device State** element
3. Select **Tesla Meters** as the device
4. Select **`batteryState_combined`** as the state
5. Set the image folder to `PowerwallImages/Device/Combined/`

Indigo will automatically select the image matching the current state string (e.g. `charging_73` → `powerwall_comb+charging_73.png`).

### Step 2 — Add power readings

Add **Device State** labels for each power value:

| Label | Device | State |
|---|---|---|
| Solar | Tesla Meters | `SolarkW` |
| Grid | Tesla Meters | `GridkW` |
| Home | Tesla Meters | `HomekW` |
| Battery | Tesla Meters | `BatterykW` |
| Charge % | Tesla Battery | `chargeCP` |
| Mode | Tesla Battery | `batteryMode` |
| Reserve | Tesla Battery | `batteryReservePercentage` |
| Time left | Tesla Battery | `battery_remainingTimeText` |
| Tariff | Tesla Site Info | `current_tarriff_name` |

### Step 3 — Add status indicators

Use the boolean states with the included boolean images:

| State | True image | False image |
|---|---|---|
| `solarGenerating` | `solarGenerating+True.png` | `solarGenerating+False.png` |
| `sendingtoGrid` | `sendingtoGrid+True.png` | `sendingtoGrid+False.png` |
| `batteryCharging` | `BatteryDischarging+True.png` | `BatteryDischarging+False.png` |
| `gridConnected` | `GridLine+True.png` | `GridLine+False.png` |

These boolean images are in `PowerwallImages/Device/`.

---

## Using the Small Combined Images

The `Combined-small/` folder contains identically-named versions at a reduced resolution — useful for compact control pages or dashboards where space is limited:

`PowerwallImages/Device/Combined-small/powerwall_comb_small+{state}_{pct}.png`

Same state/percentage convention as the full-size versions.
