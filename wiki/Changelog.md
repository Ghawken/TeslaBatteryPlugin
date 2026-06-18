![Tesla Battery Plugin](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/wiki/banner.png)

# Changelog


---

## 1.0.35 — 2026-06-18
- Fixed 403 Forbidden errors from Tesla Owner API caused by Tesla enforcing TLS 1.3
- Added `TLSAdapter` to bundled `teslapy` library — pins all HTTPS connections to TLS 1.3 only
- Fix is equivalent to [teslapy PR #176](https://github.com/tdorssers/TeslaPy/pull/176) (merged 2026-06-15, not yet in a release)
- Removed `battery_list()` debug call from `getauthTokenOnline()` that crashed the background thread on every loop restart
- `getsiteInfo()` now returns `""` on exception (previously returned `None`, causing callers to misread failure as success)
- `getsiteInfo()` logs a clear human-readable message on 403 rather than a stack trace

## 1.0.30 — 2026-05-31
- Add comprehensive wiki documentation
- Update README with banner, feature table, wiki links, and inline images

## 1.0.27 — 2026-05-31
- Fixed `TariffResolver` exceptions crashing `runConcurrentThread` — now caught and logged gracefully
- Fixed grid fault trigger never firing on first fault appearance (condition was inverted)
- Fixed grid fault log message showing "BLANK" when faults were present
- Fixed `get_tariff_rates_online` unbound `dev` variable when no battery devices exist
- Fixed `setOperationalModeOnline` `TypeError` on auth failure (`datareturned` is always `None`)
- Fixed JSON string injection in `sendcommand` local login payload — replaced with `json.dumps()`
- Fixed battery level image not updating at exactly 25% charge
- Fixed `SystemIslandedReady` grid state not handled — now treated same as `SystemIslandedActive`
- Fixed `fillmetersinfo` exception handler logging wrong function name (`fillsiteinfo`)
- Fixed OAuth `if not self.tesla.authorized:` guard (was commented out) — prevents unnecessary token refresh on every call
- Removed discarded `getsiteInfoOnline()` call in `setOperationalModeOnline`
- Removed `TypeError`-causing `'authorization_required' in datareturned` check
- Changed bare macOS version `info` log to `debug`

## 1.0.26 — 2025
- Add `batteryState_combined` state combining activity state + integer charge percentage
  (format: `idle_20`, `charging_25`, `discharging_50`)
- Add 300 Combined device images for all states at every charge level (1–100)
- Add Combined-small image set

## 1.0.25 — 2025
- Add `batteryState_combined` initial implementation

## 1.0.20 — 2025
- Add `batteryState` string state: `idle`, `charging`, `discharging`

## 1.0.16 — 2024
- Fix error logging
- Fix reversal of tariff rate and name fields
- Read Tesla TOU tariff information online, update current tariff rate period every 60 seconds
- Allows triggering on tariff changes (Off-Peak, Peak, Shoulder etc.)

## 1.0.15 — 2024
- Read Tesla tariff information from online API
- Expose current TOU period name and rate as device states on Tesla Site Info

## 1.0.8 — 2024
- Fix logic in online update loop
- Add backup time remaining (online) — `battery_backtimeRemaining` and `battery_remainingTimeText`
- Accelerated remaining-time polling during grid outage (every 20 seconds)

## 1.0.5 — 2024
- Proactive token refresh when access token nears expiry
- Additional checks for online configuration validity

## 1.0.2 — 2024
- Logic fixes for online update scheduling
- Add backup time remaining states

## 1.0.1 — 2024
- Time remaining logic improvements

## 0.9.0 — 2023
- Update bundled TeslaPy library
- Adjust online API endpoints for Tesla backend changes

## 0.8.11 — 2023
- Fix online authentication path
- Document refresh token requirement

## 0.8.10 — 2023
- Fix online API connection stability

## 0.8.9 — 2023
- Exception handling improvements for Python 3
- Various Python 3 compatibility fixes

## 0.8.8 — 2023
- Minor stability fixes

## 0.8.6 — 2023
- Python 3 port complete
- Adopt TeslaPy library for online OAuth authentication
- Use TeslaPy solely for access token retrieval; direct `requests` calls for all API endpoints
- Refresh Token workflow: obtain once from third-party app, paste into Plugin Config

## 0.8.5 — 2023
- Python 3 version
- Updates for Tesla online API changes (1 March 2023)

## 0.4.3 — 2022
- Add `setconfigCompleted` and `setsitemasterRun` gateway commands
- Minor stability improvements

## 0.4.2 — 2022
- Fix pairing token handling for local gateway auth

## 0.4.1 — 2022
- Remove test auth token from release build

## 0.4.0 — 2022
- Add **Set Operational Mode** action
- Add Plugin Config settings for online credentials
- Initial online API (mode/reserve control) implementation

## 0.3.9 — 2022
- Add safety checks for missing fields in `site_info` response
- Remove Indigo 7.3 update checker code

## 0.3.6 — 2021
- Tesla software 1.20.0+ compatibility (HTTPS required)
- Switch local API calls from HTTP to HTTPS with `verify=False`
- Move to `requests` library (away from `curl` subprocess) for reliability
- Add connection timeout handling and IP address validation

## 0.3.5 — 2021
- Initial 1.20.0 compatibility work
- SSL / HTTPS local gateway support

## 0.3.0 — 2021
- Work-in-progress fix for Tesla 1.20.0 SSL changes
- Threading improvements for timeout handling

## 0.2.7 — 2020
- Add `timeGridLoss` and `timeGridUp` timestamps to Grid Status device
- Add `gridFault` trigger
- Add `gridLoss` and `gridRestored` triggers
- More Grid Status device states

## 0.2.2 — 2020
- Add triggers for battery events
- More device images
- Fix: gateway offline detection
- Fix: log file not saving in some configurations

## 0.2.1 — 2020
- Add triggers for various events
- More images for control pages

## 0.1.9 — 2019
- Change data source endpoint for meter data
- Add boolean states: `sendingtoGrid`, `solarGenerating`, `batteryCharging`, `batteryDischarging`
- Ignore ±0.1 kW rounding noise in battery readings

## 0.1.5 — 2019
- Plugin Store release
- Add battery charge level images for control pages
- Add `batteryState` image support
- Add `gridUsage` boolean state
- Add `batteryCharging` boolean state
- Additional control panel images

## 0.1.1 — 2019
- Plugin Store release
- More battery images for control pages

## 0.0.9 — 2018
- First public release

## 0.0.5 — 2018
- Initial proof of concept
