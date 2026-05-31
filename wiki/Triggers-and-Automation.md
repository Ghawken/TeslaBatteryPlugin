![Tesla Battery Plugin](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/wiki/banner.png)

# Triggers & Automation

The plugin exposes rich device states that Indigo can watch with standard **Device State Change** triggers. Use these to build automations that react to grid events, battery activity, and solar generation.

> **Note:** The plugin's internal trigger handling code defines `gridLoss`, `gridRestored`, `batteryCharging`, and `batteryDischarging` events, but there is no `Events.xml` in the bundle so these do not appear as selectable plugin event types in the Indigo Triggers UI. Use the **Device State Change** trigger type instead — it is equally capable and more flexible.

---

## How to Create a Trigger

1. In Indigo, open **Triggers** and click **+**
2. Choose **Device State Change** as the trigger type
3. Select the relevant plugin device (Tesla Grid Status, Tesla Meters, etc.)
4. Select the state to watch and the condition (equals, changes, becomes True/False, etc.)
5. Add actions

---

## Grid Events

### Grid Loss

**Watch:** `Tesla Grid Status → gridConnected` **becomes** `False`

This fires the moment the gateway reports the grid is down and the Powerwall is islanding.

**Typical automations:**
- Turn off high-draw appliances (EV charger, pool pump, electric dryer)
- Send notification: "Grid power lost — Powerwall islanded. Battery at X%"
- Set operational mode to `backup` via the Set Operational Mode action
- Log the loss time (also available as `timeGridLoss` device state)

### Grid Restored

**Watch:** `Tesla Grid Status → gridConnected` **becomes** `True`

Fires when the gateway reports `SystemGridConnected` after an islanded state.

**Typical automations:**
- Re-enable appliances turned off during the outage
- Send notification: "Grid power restored"
- Switch battery back to `autonomous` mode
- Log restore time (also available as `timeGridUp`)

### Grid Fault

**Watch:** `Tesla Grid Status → gridFaults` **changes**

The `gridFaults` state holds a JSON string — it is `[]` when no faults exist. Trigger on it changing to catch any new fault event.

**Typical automations:**
- Log fault data to an Indigo variable
- Send a notification with the fault string for later review

---

## Battery Events

### Battery Starts Discharging

**Watch:** `Tesla Meters → batteryDischarging` **becomes** `True`

Fires when battery discharge power exceeds 150 W.

### Battery Starts Charging

**Watch:** `Tesla Meters → batteryCharging` **becomes** `True`

Fires when battery charge power exceeds 100 W.

### Battery State Change

**Watch:** `Tesla Meters → batteryState` **changes**

The `batteryState` string cycles between `idle`, `charging`, and `discharging`. Trigger on changes to catch any transition, or use **equals** a specific value to trigger only on one state.

---

## Solar Events

### Solar Generation Starts

**Watch:** `Tesla Meters → solarGenerating` **becomes** `True`

Fires when solar output exceeds 95 W.

### Exporting to Grid

**Watch:** `Tesla Meters → sendingtoGrid` **becomes** `True`

Fires when grid export exceeds 100 W.

**Typical automation:**
- Activate pool pump or hot water boost to use excess solar

---

## Tariff Events

### Tariff Period Changes

**Watch:** `Tesla Site Info → current_tarriff_name` **changes**

Fires whenever the TOU period transitions (e.g. Off-Peak → Peak). You can also use **equals** a specific period name to trigger on entering a known tariff window.

**Typical automations:**

```
Peak tariff starts:
  Trigger:  current_tarriff_name equals "Peak"
  Action:   Set Operational Mode → backup, reserve 100%

Off-peak starts:
  Trigger:  current_tarriff_name equals "Off-Peak"
  Action:   Set Operational Mode → autonomous, reserve 20%
```

> Tariff data requires Online Access and is refreshed every 60 seconds.

---

## Useful Conditions to Combine

Use Indigo **Conditions** (added to any trigger) to refine when automations fire:

| Condition | Device | State | Use case |
|---|---|---|---|
| Battery above threshold | Tesla Battery | `chargeCP` > 50 | Only act if battery has enough charge |
| Solar generating | Tesla Meters | `solarGenerating` = True | Only act when sun is up |
| Grid connected | Tesla Grid Status | `gridConnected` = True | Skip during outages |
| Mode check | Tesla Battery | `batteryMode` = `autonomous` | Only change mode if not already set |

---

## Example: Full Grid-Loss Automation

**Trigger:** `Tesla Grid Status → gridConnected` becomes `False`

**Actions:**
1. Turn off — EV charger device
2. Turn off — Pool pump device
3. Send push notification: "⚡ Grid lost — Powerwall islanded. Battery at [Tesla Battery → chargeCP]%"
4. Set Operational Mode → `backup`, reserve `100%`
5. Set variable `gridLossTime` = current timestamp

**Paired restore trigger:** `Tesla Grid Status → gridConnected` becomes `True`

**Actions:**
1. Send notification: "✅ Grid restored. Battery at [Tesla Battery → chargeCP]%"
2. Set Operational Mode → `autonomous`, reserve `20%`
3. Turn on — Pool pump device
4. Set variable `gridRestoreTime` = current timestamp
