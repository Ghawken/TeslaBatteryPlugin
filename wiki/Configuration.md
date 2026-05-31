![Tesla Battery Plugin](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/wiki/banner.png)

# Configuration

Open **Plugins → Tesla Battery → Configure…** to access the Plugin Config dialog.

---

## Local Gateway

These settings control communication with your Powerwall Gateway on your LAN. They are required for all monitoring functions.

| Field | ID | Description |
|---|---|---|
| **IP Address** | `ipAddress` | Static LAN IP of the Powerwall Gateway (e.g. `192.168.1.111`). Assign a DHCP reservation in your router. |
| **Battery Customer Username/Email** | `Batusername` | Your Tesla account email. Used as the `email` field in the local login payload. |
| **Battery Password** | `Batpassword` | The local Gateway customer password — found in the Tesla app under Gateway → Settings → Local Access. |

### Buttons

| Button | When visible | What it does |
|---|---|---|
| **Check Connection Gateway Devices** | Before first connect | Tests the IP + credentials against `/api/site_info/site_name`. Sets `loginOK`. |
| **Generate Tesla Devices** | After successful check | Creates the four plugin devices and fills them with live data. |

---

## Online Access & Refresh Token

These settings are only needed for **online features**: reading backup reserve / battery mode / time remaining / tariff data, and for using the **Set Operational Mode** and **Change Battery Reserve** actions.

| Field | ID | Description |
|---|---|---|
| **Allow Online Communication** | `allowOnline` | Master switch. Uncheck to disable all Tesla cloud API calls. |
| **Tesla Username/Email** | `username` | Your Tesla account email — used to key the token cache file. |
| **refreshToken** | `refreshToken` | OAuth refresh token obtained from a third-party tool (e.g. Teslascope). Paste once; the plugin caches the resulting session. |

> **Token lifecycle:** The plugin uses [TeslaPy](https://github.com/tdorssers/TeslaPy) to manage OAuth. On first use it calls `refresh_token()` to obtain an access token (valid 8 hours), which is cached in `cache.json` in the plugin bundle. Subsequent starts reuse the cached token until it expires. The refresh token itself is valid for roughly 45–90 days — when it expires you will see `login_required` in the log and need to generate a new one.

---

## Update Frequency

| Field | ID | Default | Description |
|---|---|---|---|
| **Frequency of Update Checks (hours)** | `updateFrequency` | `24` | How often to check GitHub for a plugin update. |

---

## Debug Settings

| Field | ID | Description |
|---|---|---|
| **Debug Extra 1** | `debugextra` | Verbose logging for every polling cycle — useful when diagnosing data issues. |
| **Debug Triggers** | `debugtriggers` | Logs each trigger evaluation and which ones fire. |
| **Debug level** | `showDebugLevel` | Sets the Indigo log verbosity level. |

| Level | Value | Use |
|---|---|---|
| Detailed Debugging Messages | `5` | Everything — very noisy |
| Debugging Messages | `10` | Standard debug output |
| Informational Messages | `20` | Normal operation (recommended) |
| Warning Messages | `30` | Warnings and above only |
| Error Messages | `40` | Errors only |
| Critical Errors Only | `50` | Minimal |

You can also toggle debug on/off from **Plugins → Tesla Battery → Toggle Debugging** without reopening the config dialog.

---

## Polling Intervals

The plugin uses an internal timer loop. These intervals are hardcoded:

| Data | Local/Online | Interval |
|---|---|---|
| Meter aggregates (Solar/Grid/Home/Battery watts) | Local | Every 15 seconds |
| Grid status | Local | Every 10 seconds |
| Grid faults | Local | Every 2 minutes |
| Site info | Local | Every 10 minutes |
| Battery state of charge | Local | Every 60 seconds |
| Battery remaining time | Online | Every 10 minutes (every 20 seconds during grid outage) |
| Tariff current rate | Online | Every 60 seconds |
| Online site info (mode, reserve, storm mode) | Online | Every hour (or at startup if site ID unknown) |

---

## Plugin Config Field Reference (PluginConfig.xml IDs)

For scripting or automation that reads `pluginPrefs`:

```
ipAddress           — Gateway IP
Batusername         — Gateway email
Batpassword         — Gateway local password
allowOnline         — bool: enable cloud API
username            — Tesla account email (for OAuth)
refreshToken        — OAuth refresh token string
showDebugLevel      — int log level (5/10/20/30/40/50)
debugextra          — bool: verbose logging
debugtriggers       — bool: trigger debug logging
updateFrequency     — float: hours between update checks
```
