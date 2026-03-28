#!/bin/bash
# Captures real whois CLI output for every query the test suite makes.
# Naming: {server}_{sanitized-query}.txt  or  default_{sanitized-query}.txt
# "/" -> "-"   " " -> "_"   "> " -> "gt-"

set -e
cd "$(dirname "$0")/.."
mkdir -p test/data

cap_h() {          # whois -h SERVER QUERY  ->  SERVER_safe-query.txt
    local server="$1"
    local query="$2"
    local safe="${query//\//-}"
    safe="${safe// /_}"
    safe="${safe/>_/gt-}"
    local file="test/data/${server}_${safe}.txt"
    echo "  whois -h $server \"$query\"  ->  $file"
    whois -h "$server" "$query" > "$file" 2>/dev/null || true
}

cap_default() {    # whois QUERY  ->  default_safe-query.txt
    local query="$1"
    local safe="${query//\//-}"
    safe="${safe// /_}"
    local file="test/data/default_${safe}.txt"
    echo "  whois \"$query\"  ->  $file"
    whois "$query" > "$file" 2>/dev/null || true
}

echo "=== 5 RIRs x 5 fixture resources ==="
for server in whois.ripe.net whois.arin.net whois.lacnic.net whois.apnic.net whois.afrinic.net; do
    for query in "83.231.214.0/24" "8.8.8.0/24" "181.64.132.0/24" "1.1.1.0/24" "196.223.14.0/24"; do
        cap_h "$server" "$query"
    done
done

echo "=== ARIN start-IP lookup (prefixLookupArin) ==="
cap_h "whois.arin.net" "8.8.8.0"

echo "=== ARIN r> suballocations ==="
cap_h "whois.arin.net" "r > 8.8.8.0/24"

echo "=== Default (no -h) whois ==="
cap_default "8.8.8.0/24"
cap_default "8.8.8.0"

echo ""
echo "=== Files in test/data ==="
ls -1 test/data/
echo ""

# Check r> file for NET handles that would trigger handler follow-up queries
echo "=== Scanning r> output for NET handles ==="
RFILE="test/data/whois.arin.net_r_>_8.8.8.0-24.txt"
if [ ! -f "$RFILE" ]; then
    RFILE="test/data/whois.arin.net_r_gt-8.8.8.0-24.txt"
fi
if [ -f "$RFILE" ]; then
    grep -oE 'NET-[0-9-]+' "$RFILE" | sort -u || echo "(no NET handles found)"
fi
