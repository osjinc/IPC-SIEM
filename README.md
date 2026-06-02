# Informatica PowerCenter SIEM Integration

This project provides a lightweight, agentless solution for exporting audit and security events from Informatica PowerCenter (IPC) 10.5.5 to a SIEM system (e.g., KUMA).

## 1. Architectural Overview
The integration follows a **Pull-model** design:

* **Agentless:** No third-party software is installed on the IPC server.
* **Non-intrusive:** Minimal CPU/RAM impact using `infacmd` with strict concurrency control.
* **Reliable:** HWM (High-Water Mark) state management ensures no data loss during network outages.
* **Atomic:** Temporary files are used to prevent race conditions during SIEM data collection.

## 2. Directory Structure
* `/opt/informatica/scripts/siem/`: **App Directory** (Script, Logs, HWM state). InfoSec has NO access.
* `/opt/informatica/siem_export/`: **Staging Area** (Target for JSON files). InfoSec has Read/Delete access.

## 3. Setup Instructions

### 3.1 IPC Service Account
Create a Read-Only service account in Informatica Administrator with permissions for the Domain and all monitored Integration Services.

### 3.2 Secure Password
Encrypt your password using the Informatica utility:
1. `cd /opt/informatica/10.5.5/server/bin`
2. `./pmpasswd Your_Password -e CRYPT_DATA`
3. Insert the resulting string into the `INFA_PASS_ENC` variable within the script.

### 3.3 Permissions
```bash
# App Directory
chmod 700 /opt/informatica/scripts/siem
# Export Directory
chmod 770 /opt/informatica/siem_export

### 4. Deployment
1. Place `infa_siem_export.sh` into `/opt/informatica/scripts/siem/`.
2. Make it executable:
   `chmod +x /opt/informatica/scripts/siem/infa_siem_export.sh`
3. Add to `crontab` (running every 10 minutes):
   `*/10 * * * * /opt/informatica/scripts/siem/infa_siem_export.sh > /dev/null 2>&1`

### 5. InfoSec Integration Contract
1. **Fetch:** Collect files via `*.json` mask from `/opt/informatica/siem_export/`.
2. **Cleanup:** Delete successfully processed `*.json` files.
3. **Format:** Single-line JSON (NDJSON).
