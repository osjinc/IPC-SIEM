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
```

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

**Sample Payload (JSON):**
```json
{"Vendor": "Informatica", "Source": "DOMAIN", "EventTime": "2026-06-02 15:30:00", "Severity": "INFO", "Category": "Security", "EventCode": "UM_10059", "Message": "User [Administrator] logged in successfully from host [192.168.1.50]."}
{"Vendor": "Informatica", "Source": "IS_PROD_01", "EventTime": "2026-06-02 15:32:14", "Severity": "INFO", "Category": "LM", "EventCode": "LM_36488", "Message": "Session task instance [s_m_DWH_LOAD] : [Execution terminated successfully.]"}
```

## KUMA SIEM Integration (CEF Format)

This repository includes a dedicated script (`infa_siem_export_cef.sh`) for SIEM systems that natively support the Common Event Format (CEF), such as Kaspersky KUMA.

### Why CEF?
Using CEF offloads the parsing overhead from the SIEM collector. The script maps Informatica proprietary log structures directly into standard CEF headers (`Device Vendor`, `Device Product`, `Signature ID`, `Severity`) and appends specific context (like the Service Name) into the `Extension` field.

### Deployment Differences for CEF
1. **Script:** Deploy `infa_siem_export_cef.sh` instead of the JSON version.
2. **Permissions:** The setup remains identical (read-only IPC account, encrypted password via `INFA_DEFAULT_DOMAIN_PASSWORD`).
3. **Timezone Synchronization:** Ensure the IPC server timezone (e.g., UTC+7 / Indochina Time) exactly matches the SIEM collector's expectations. The High-Water Mark (HWM) relies on OS time; a mismatch can cause event drops.

### InfoSec Integration Contract (KUMA Configuration)
When configuring the KUMA Collector, the InfoSec team must use the following parameters:
* **Connector Type:** File
* **Parser:** CEF (Native)
* **File Mask:** `*.cef` from the staging directory (`/opt/informatica/siem_export/`).
* **Cleanup Strategy:** Delete files immediately after successful ingestion.

### Sample Payload (CEF)
```text
CEF:0|Informatica|PowerCenter|10.5.5|UM_10059|Event|INFO|src=DOMAIN msg=User [Administrator] logged in successfully from host [192.168.1.50].
CEF:0|Informatica|PowerCenter|10.5.5|LM_36488|Event|INFO|src=IS_PROD_01 msg=Session task instance [s_m_DWH_LOAD] : [Execution terminated successfully.]
