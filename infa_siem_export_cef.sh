#!/bin/bash
# ==============================================================================
# Author: osjinc (https://github.com/osjinc/IPC-SIEM)
# License: MIT
# Date: 2026-06-03
# ==============================================================================
# Script for exporting Informatica security and operational logs for SIEM (CEF Format)
# ==============================================================================

# --- 1. ENVIRONMENT VARIABLES AND PATHS ---
INFA_HOME="/opt/informatica/10.5.5"
DOMAIN_NAME="Domain_PROD"
INFA_USER="siem_reader"

# Системная переменная для авторизации (замените на свой шифрованный пароль)
export INFA_DEFAULT_DOMAIN_PASSWORD="INSERT_ENCRYPTED_STRING_HERE"

APP_DIR="/opt/informatica/scripts/siem"
LOCK_FILE="/tmp/infa_siem_export_cef.lock"
STATE_FILE="${APP_DIR}/hwm_state.txt"
SCRIPT_LOG="${APP_DIR}/siem_export.log"

EXPORT_DIR="/opt/informatica/siem_export"
MAX_DIR_SIZE_MB=100

FILE_TS=$(date +"%Y%m%d_%H%M%S")
TMP_RAW_LOG="${APP_DIR}/raw_export_${FILE_TS}.txt"
TMP_DOMAIN="${EXPORT_DIR}/domain_${FILE_TS}.tmp"
TMP_SERVICES="${EXPORT_DIR}/services_${FILE_TS}.tmp"

# --- 2. LOCK MECHANISM & TRAP ---
if [ -f "$LOCK_FILE" ]; then
    echo "[$(date)] ERROR: Script is already running. Exiting." >> "$SCRIPT_LOG"
    exit 1
fi
touch "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"; exit' INT TERM EXIT

# --- 3. HWM LOGIC ---
if [ -f "$STATE_FILE" ]; then
    START_TIME=$(cat "$STATE_FILE")
else
    START_TIME=$(date -d "10 minutes ago" +"%Y-%m-%d %H:%M:%S")
fi
END_TIME=$(date +"%Y-%m-%d %H:%M:%S")

echo "[$(date)] Starting CEF export cycle. Period: $START_TIME to $END_TIME" >> "$SCRIPT_LOG"

run_infa() {
    $INFA_HOME/isp/bin/infacmd.sh "$@"
}

# --- 4. CEF PARSER FUNCTION ---
parse_to_cef() {
    local source_name=$1
    local output_tmp_file=$2
    local whitelist="Security|User Management|Authentication|LM_36318|LM_36488|UM_10058|UM_10059"
    
    if [ -f "$TMP_RAW_LOG" ]; then
        grep -E "$whitelist" "$TMP_RAW_LOG" | \
        awk -v src="$source_name" -F ' : ' '{
            # Очистка от лишних кавычек и переносов строк для безопасного CEF
            gsub(/"/, "\\\"", $0);
            gsub(/\n/, " ", $0);
            # Формирование строки CEF:0|Vendor|Product|Version|EventCode|Name|Severity|Extension
            printf "CEF:0|Informatica|PowerCenter|10.5.5|%s|Event|%s|src=%s msg=%s\n", $6, $2, src, $7
        }' >> "$output_tmp_file"
    fi
}

# --- 5. QUOTA CHECK ---
DIR_SIZE=$(du -mc ${EXPORT_DIR}/*.cef 2>/dev/null | grep total$ | awk '{print $1}')
DIR_SIZE=${DIR_SIZE:-0}

if [ "$DIR_SIZE" -ge "$MAX_DIR_SIZE_MB" ]; then
    echo "[$(date)] CRITICAL: Export folder full. Halting." >> "$SCRIPT_LOG"
    exit 1 
fi

# --- 6. DOMAIN EXPORT ---
run_infa GetLog -dn $DOMAIN_NAME -un $INFA_USER -st DOMAIN -fm TEXT -sd "$START_TIME" -ed "$END_TIME" -lo "$TMP_RAW_LOG" > /dev/null 2>&1
parse_to_cef "DOMAIN" "$TMP_DOMAIN"
rm -f "$TMP_RAW_LOG"

# --- 7. SERVICES EXPORT ---
SERVICES_LIST=$(run_infa isp ListServices -dn $DOMAIN_NAME -un $INFA_USER | grep -v -i "successfully" | awk '{print $1}')

for name in $SERVICES_LIST; do
    if [[ "$name" == IS_* ]]; then TYPE="IS"
    elif [[ "$name" == RS_* ]]; then TYPE="RS"
    elif [[ "$name" == WS_* ]]; then TYPE="WS"
    else continue
    fi

    run_infa GetLog -dn $DOMAIN_NAME -un $INFA_USER -st "$TYPE" -sn "$name" -fm TEXT -sd "$START_TIME" -ed "$END_TIME" -lo "$TMP_RAW_LOG" > /dev/null 2>&1
    
    parse_to_cef "$name" "$TMP_SERVICES"
    rm -f "$TMP_RAW_LOG"
    sleep 1
done

# --- 8. ATOMIC COMMIT (.cef extension) ---
[ -s "$TMP_DOMAIN" ] && mv "$TMP_DOMAIN" "${EXPORT_DIR}/domain_${FILE_TS}.cef" || rm -f "$TMP_DOMAIN"
[ -s "$TMP_SERVICES" ] && mv "$TMP_SERVICES" "${EXPORT_DIR}/services_${FILE_TS}.cef" || rm -f "$TMP_SERVICES"

# --- 9. HWM UPDATE ---
echo "$END_TIME" > "$STATE_FILE"
echo "[$(date)] CEF export cycle completed successfully. New HWM: $END_TIME" >> "$SCRIPT_LOG"

exit 0
