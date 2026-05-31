![Tesla Battery Plugin](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/wiki/banner.png)

# Triggers & Automation

The plugin fires Indigo triggers on specific events. Create trigger actions in **Indigo → Triggers** and select the plugin event type.

---

## Available Trigger Events

| Trigger ID | Device | Fires When |
|---|---|---|
| `gridLoss` | Tesla Grid Status | Grid transitions from connected → islanded |
| `gridRestored` | Tesla Grid Status | Grid transitions from islanded → connected |
| `gridFault` | Tesla Grid Status | A new grid fault is detected (fault list changes to non-empty) |
| `batteryCharging` | Tesla Meters | Battery transitions from not-charging → charging (> 100 W charge) |
| `batteryDischarging` | Tesla Meters | Battery transitions from not-discharging → discharging (> 150 W discharge) |
| `solarExporting` | Tesla Meters | Grid export transitions from not-exporting → exporting (> 100 W export) |

> Triggers fire on **state transitions only** — not repeatedly while the condition is true.

---

## Grid Events

### Grid Loss (`gridLoss`)

Fires the moment the gateway reports `SystemIslandedActive` or `SystemIslandedReady` after a connected state.

**Typical automations:**
- Turn off high-draw appliances (EV charger, pool pump, electric dryer)
- Send a push notification: "Grid power lost — Powerwall islanded"
- Log the event to a variable or file
- Activate an emergency lighting scene

**State to check alongside trigger:**
- `Tesla Grid Status → timeGridLoss` — timestamp of the loss

### Grid Restored (`gridRestored`)

Fires when the gateway reports `SystemGridConnected` after an islanded state.

**Typical automations:**
- Re-enable appliances that were turned off during outage
- Send a notification: "Grid power restored"
- Switch battery back to `autonomous` mode if you changed it during the outage

**State to check:**
- `Tesla Grid Status → timeGridUp` — timestamp of restoration

### Grid Fault (`gridFault`)

Fires when new fault data appears in the gateway fault list. Grid faults are diagnostic events logged by the Powerwall; they don't necessarily mean a full outage.

**Typical automation:**
- Log fault data to an Indigo variable for later review
- Send a notification with the raw fault string

---

## Battery Events

### Battery Charging (`batteryCharging`)

Fires when battery power flow crosses −100 W (battery drawing more than 100 W from solar or grid).

**Typical automations:**
- Update a control page indicator
- Log charging events to track daily cycles

### Battery Discharging (`batteryDischarging`)

Fires when battery power flow crosses +150 W (battery supplying more than 150 W to the home).

**Typical automations:**
- Turn on a "battery active" indicator light
- Log discharge events

---

## Solar Events

### Solar Exporting (`solarExporting`)

Fires when grid export crosses −100 W (more than 100 W being sent to the grid).

**Typical automations:**
- Log export start time
- Activate loads to consume excess generation (pool pump, hot water boost)

---

## State-Based Automation (without triggers)

For automation that reacts to a specific state value rather than a transition, use **Indigo Control Pages** or **Indigo Variables** with **Condition** checks on device states:

### Current Tariff Period

```
Condition:  Tesla Site Info → current_tarriff_name  equals  "Peak"
Action:     Set Operational Mode → backup
```

### Battery Below Threshold

```
Condition:  Tesla Battery → chargeCP  is less than  20
Action:     Send notification "Battery critically low"
```

### Solar Generating During Peak

```
Condition:  Tesla Site Info → current_tarriff_name  equals  "Peak"
            AND Tesla Meters → solarGenerating  is True
Action:     Switch operational mode to self_consumption
```

---

## Example: Full Grid-Loss Automation

A complete grid-loss action group:

1. **Turn off** EV charger device
2. **Turn off** pool pump device  
3. **Send notification** "Grid lost — Powerwall islanded. Battery at {Tesla Battery → chargeCP}%"
4. **Set operational mode** → `backup`, reserve `100%`
5. **Set variable** `gridLossTime` = current time

And on grid restore:

1. **Send notification** "Grid restored. Battery at {Tesla Battery → chargeCP}%"
2. **Set operational mode** → `autonomous`, reserve `20%`
3. **Turn on** pool pump device
4. **Set variable** `gridRestoreTime` = current time
