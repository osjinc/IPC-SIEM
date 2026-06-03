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
