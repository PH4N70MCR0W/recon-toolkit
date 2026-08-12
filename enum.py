cat > enum.sh <<'EOF'
#!/usr/bin/env bash
# Simple OSCP-style enumeration wrapper.
# Runs an initial nmap sweep, parses open ports, and fires
# per-service follow-up enumeration. Extend the case block below.

set -uo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target-ip>"
    exit 1
fi

OUTDIR="enum_${TARGET}"
mkdir -p "$OUTDIR"/{nmap,web,smb,misc}
echo "[*] Target: $TARGET   Output: $OUTDIR"

# --- Phase 1: full TCP port discovery (fast) -----------------------
echo "[*] Discovering open TCP ports..."
nmap -p- --min-rate 2000 -T4 -oG "$OUTDIR/nmap/allports.gnmap" "$TARGET" >/dev/null

# Pull the open port numbers out of the greppable output
PORTS=$(grep -oP '\d+/open' "$OUTDIR/nmap/allports.gnmap" | cut -d/ -f1 | paste -sd,)
if [[ -z "$PORTS" ]]; then
    echo "[!] No open ports found."
    exit 0
fi
echo "[+] Open ports: $PORTS"

# --- Phase 2: service/version scan on those ports ------------------
echo "[*] Running service + default-script scan..."
nmap -sC -sV -p "$PORTS" -oN "$OUTDIR/nmap/services.nmap" \
     -oG "$OUTDIR/nmap/services.gnmap" "$TARGET" >/dev/null

# --- Phase 3: per-service follow-up --------------------------------
# Loop over "port/service" pairs from the version scan.
grep -oP '\d+/open/tcp//\w+' "$OUTDIR/nmap/services.gnmap" | while IFS=/ read -r port _ _ _ service; do
    echo "[*] Follow-up for $service ($port)"
    case "$service" in
        http)
            command -v whatweb  >/dev/null && whatweb "http://$TARGET:$port" > "$OUTDIR/web/whatweb_$port.txt" 2>&1
            command -v feroxbuster >/dev/null && \
                feroxbuster -u "http://$TARGET:$port" -o "$OUTDIR/web/ferox_$port.txt" -q 2>&1 &
            ;;
        https|ssl*)
            command -v whatweb >/dev/null && whatweb "https://$TARGET:$port" > "$OUTDIR/web/whatweb_${port}_ssl.txt" 2>&1
            ;;
        microsoft-ds|netbios-ssn)
            command -v enum4linux-ng >/dev/null && \
                enum4linux-ng -A "$TARGET" > "$OUTDIR/smb/enum4linux_$port.txt" 2>&1
            command -v smbclient >/dev/null && \
                smbclient -N -L "//$TARGET" > "$OUTDIR/smb/shares_$port.txt" 2>&1
            ;;
        ftp)
            echo "anonymous login? test manually: ftp $TARGET $port" | tee "$OUTDIR/misc/ftp_$port.txt"
            ;;
        ssh)
            echo "ssh on $port — note version, check for weak creds later" | tee "$OUTDIR/misc/ssh_$port.txt"
            ;;
        *)
            echo "[?] No handler for '$service' on $port — enumerate manually." | tee "$OUTDIR/misc/todo_$port.txt"
            ;;
    esac
done

wait
echo "[+] Done. Review $OUTDIR/"
EOF
chmod +x enum.sh
