![Tesla Battery Plugin](https://raw.githubusercontent.com/Ghawken/TeslaBatteryPlugin/python3_/PowerwallImages/wiki/banner.png)

# Installation

## Requirements

Before installing, make sure you have:

- A **Tesla Powerwall** with a Gateway reachable on your LAN
- A **static / reserved IP address** set on your router for the Gateway (e.g. `192.168.1.111`)
- **Indigo Domo 2022.1+** running on macOS
- *(Online features only)* Your Tesla account email and a Refresh Token — see [Configuration](Configuration#online-access-refresh-token)

---

## 1 · Install the Plugin

Download the latest release `.indigoPlugin` bundle from:

**[https://github.com/Ghawken/TeslaBatteryPlugin/releases/](https://github.com/Ghawken/TeslaBatteryPlugin/releases/)**

Double-click the downloaded file. Indigo will prompt you to install it. Click **Install and Enable**.

---

## 2 · Configure the Gateway Connection

After the plugin enables, open **Plugins → Tesla Battery → Configure…**

### Local Gateway

Fill in the three fields under the **Tesla Battery Gateway IP Address** section:

| Field | What to enter |
|---|---|
| **IP Address** | Static LAN IP of your Gateway, e.g. `192.168.1.111` |
| **Battery Customer Username/Email** | Your Tesla account email (same one used in the Tesla app) |
| **Battery Password** | The local Gateway customer password (shown in the Tesla app under Gateway → Manage → Local Access → Customer) |

> **Finding your local password:** The local gateway password is shown in the Tesla app under your Powerwall settings. Look for a **Local Access** or **Gateway** section — the exact path varies by app version. The password is typically a short alphanumeric code. The username is always `customer` internally, but enter your Tesla account email in the email field.

Click **Check Connection Gateway Devices**. If the Gateway is reachable, the button will change to **Generate Tesla Devices**.

---

## 3 · Generate Devices

Click **Generate Tesla Gateway Devices**.

The plugin will create four devices inside a folder called **Tesla Battery Gateway**:

| Device | What it represents |
|---|---|
| Tesla Site Info | Local gateway site configuration |
| Tesla Battery | State of charge, mode, reserve, time remaining |
| Tesla Grid Status | Grid connection state, loss/restore times, faults |
| Tesla Meters | Live power flow — solar, battery, grid, home |

The devices are populated immediately with live data from your Gateway.

---

## 4 · (Optional) Enable Online Features

Online features give you access to data that the local API doesn't expose and allow you to **control** the battery remotely.

1. Tick **Allow Online Communication** in Plugin Config
2. Enter your **Tesla Account Email**
3. Obtain a **Refresh Token** and paste it in — see below

### Obtaining a Refresh Token

Tesla no longer provides username/password API access. You need a Refresh Token generated via OAuth. The easiest method:

1. Visit **[https://teslascope.com/help/generating-tokens](https://teslascope.com/help/generating-tokens)**
2. Follow the instructions to authorise and copy the `refresh_token` value
3. Paste it into the **refreshToken** field in Plugin Config

> Refresh tokens expire periodically (roughly every 45–90 days). When the plugin logs `login_required: The refresh_token is invalid`, generate a new one and paste it in.

---

## 5 · Verify Everything is Working

Check the Indigo Event Log. You should see:

```
Tesla Battery    Setting up New Token Session Data
Tesla Battery    LoginTime: 2026-05-31T…
Tesla Battery    Date TimeStamp 1 hour in future = …
```

And the four devices should show **Online** status in the Indigo device list.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| "Please set Battery password and username" | Local credentials not entered | Fill in IP, email, and password in Plugin Config |
| "Connection cannot be Established" | Wrong IP or gateway unreachable | Check static IP and that the Mac can ping the gateway |
| `login_required: The refresh_token is invalid` | Refresh token expired or revoked | Generate a new one from Teslascope |
| `403 Client Error: forbidden … /api/1/products` | Tesla enforcing TLS 1.3 (June 2026+) | Upgrade to v1.0.35+ which pins connections to TLS 1.3 |
| Devices show Offline after a few minutes | Local session expired and re-login failing | Check `batPassword` — special characters require no quoting, just enter literally |
| Online states not updating | `allowOnline` not ticked, or no refresh token | Enable online access and add token |

For detailed debug output, enable **Detailed Debugging Messages** in Plugin Config → Debug level, or use **Plugins → Tesla Battery → Toggle Debugging**.
