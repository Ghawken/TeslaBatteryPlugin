![Tesla Battery Plugin](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/wiki/banner.png)

# Actions

The plugin provides two Indigo actions for controlling the Powerwall via the Tesla cloud API. Both require **Online Access** to be enabled and a valid **Refresh Token** in Plugin Config.

> These actions communicate with `owner-api.teslamotors.com`. They depend on the Tesla API being available and may fail if Tesla makes API changes. Local monitoring continues regardless.

---

## Set Operational Mode

**Action ID:** `setOperationMode`  
**Callback:** `setOperationalModeOnline`

Changes the Powerwall's operational mode and optionally sets the backup reserve percentage in the same call.

### Parameters

| Field | Type | Options | Description |
|---|---|---|---|
| **Operational Mode** | Menu | `self_consumption`, `autonomous`, `backup` | The mode to set |
| **Alter Battery Backup Reserve?** | Checkbox | — | Tick to also update the reserve % |
| **Battery Reserve Percentage** | Text | 0–100 | Reserve % (visible only when checkbox ticked) |

### Mode Descriptions

| Mode | Tesla App Name | Behaviour |
|---|---|---|
| `self_consumption` | Self-Powered | Prioritises using battery to power home; grid is used as last resort |
| `autonomous` | Time-Based Control | Battery charged/discharged according to your TOU schedule |
| `backup` | Backup-Only | Battery held in reserve for outages; not used for daily consumption |

### Example Use Cases

**Peak tariff switching** — When your TOU tariff enters peak hours, switch to `backup` to preserve charge:
```
Trigger:  Tesla Site Info → current_tarriff_name changes to "Peak"
Action:   Set Operational Mode → backup, reserve 100%
```

**Off-peak charging** — At night when rate drops, switch back to let it charge:
```
Trigger:  Time of day 10:00 PM
Action:   Set Operational Mode → autonomous, reserve 20%
```

**Manual discharge** — Force battery to supply the home:
```
Action Group:  Set Operational Mode → self_consumption, reserve 5%
```

---

## Change Battery Reserve Percentage

**Action ID:** `setBatteryReserve`  
**Callback:** `setBatteryReserve`

Sets the backup reserve percentage independently, without changing the operational mode.

### Parameters

| Field | Type | Description |
|---|---|---|
| **Battery Reserve Percentage** | Text | A number from 0–100 representing the minimum charge the battery holds for backup |

### What the Reserve Does

The backup reserve is the minimum battery charge that Powerwall will always keep available for a grid outage. For example:
- Reserve = `20` → Powerwall uses down to 20% for daily consumption; holds the last 20% for outages
- Reserve = `100` → Battery never used for daily consumption (equivalent to backup-only mode)
- Reserve = `0` → Battery can fully discharge for daily use

### Retry Behaviour

The action automatically retries once on failure:
1. First attempt — calls `/api/1/energy_sites/{id}/backup`
2. On failure — waits 3 seconds, refreshes the auth token, retries once
3. On second failure — logs an error and gives up

---

## Action Availability Requirements

Both actions will silently fail if:

- `allowOnline` is `False` in Plugin Config
- `username` is empty
- `refreshToken` is empty or expired
- The Tesla cloud API is unreachable

Check the Indigo Event Log for error messages. Enable **Debug Extra** in Plugin Config for full request/response detail.
