#!/usr/bin/env bash
# Capture a REAL 802.11 sample from your dongle and bundle it as a test fixture.
#
# Why bother, when make_fixture.py already generates one?
#
# Because the synthetic fixture is *too clean*. I built it, so it contains
# exactly the shapes I expected. Real captures contain things I did not think
# of: several antenna signal values per frame, fields absent on some frames and
# present on others, truncated frames, FCS errors, A-MPDU aggregation, QoS data
# subtypes, vendor information elements.
#
# A parser that passes only against its author's imagination is not tested.
#
# Run this once on the ThinkPad, send the resulting .tar.gz back, and it
# becomes a permanent CI fixture. Capture once, test forever — including on
# machines that have never seen a radio.
#
# Usage:  sudo ./scripts/capture-fixture.sh wlan1 36 60

set -euo pipefail

IFACE="${1:-wlan1}"
CHANNEL="${2:-36}"
DURATION="${3:-60}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="/tmp/wd-fixture-${STAMP}"

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo — monitor mode and capture both need root." >&2
    exit 1
fi

mkdir -p "$OUT"
echo "== wd-probe fixture capture =="
echo "   interface : $IFACE"
echo "   channel   : $CHANNEL"
echo "   duration  : ${DURATION}s"
echo

# ── 1. Record what the hardware IS. Without this the pcap is uninterpretable ──
echo "[1/4] Recording adapter metadata…"
{
    echo "### captured_at_utc"; date -u -Is
    echo; echo "### uname"; uname -a
    echo; echo "### os"; (cat /etc/os-release 2>/dev/null || true)
    echo; echo "### lsusb"; (lsusb || true)
    echo; echo "### ethtool -i $IFACE"; (ethtool -i "$IFACE" || true)
    echo; echo "### iw dev $IFACE info"; (iw dev "$IFACE" info || true)
    echo; echo "### iw list (interface modes + frequencies)"
    (iw list || true)
} > "$OUT/adapter-info.txt" 2>&1
echo "      → adapter-info.txt"

# ── 2. Monitor mode ───────────────────────────────────────────────────────────
echo "[2/4] Setting monitor mode on $IFACE…"
if ! iw dev "$IFACE" info | grep -q "type monitor"; then
    ip link set "$IFACE" down
    iw dev "$IFACE" set monitor control
    ip link set "$IFACE" up
    echo "      → switched to monitor mode"
else
    echo "      → already in monitor mode"
fi

# Lock the channel. Never capture a fixture while hopping — see ADR-19.
if ! iw dev "$IFACE" set channel "$CHANNEL" HT20 2>/dev/null; then
    iw dev "$IFACE" set channel "$CHANNEL"
fi
echo "      → locked to channel $CHANNEL"

# ── 3. Capture ────────────────────────────────────────────────────────────────
echo "[3/4] Capturing ${DURATION}s…"
dumpcap -i "$IFACE" -B 128 -a "duration:$DURATION" \
        -w "$OUT/real_wifi.pcap" 2>&1 | tee "$OUT/dumpcap-output.txt"

# ── 4. Summarise so we know what is in it before it is shared ────────────────
echo "[4/4] Summarising…"
{
    echo "### capinfos"; (capinfos "$OUT/real_wifi.pcap" || true)
    echo; echo "### frame type counts"
    tshark -r "$OUT/real_wifi.pcap" -T fields -e wlan.fc.type 2>/dev/null \
        | sort | uniq -c | sed 's/^/  /'
    echo; echo "### retry frames / total"
    echo "  retry: $(tshark -r "$OUT/real_wifi.pcap" -Y 'wlan.fc.retry==1' 2>/dev/null | wc -l)"
    echo "  total: $(tshark -r "$OUT/real_wifi.pcap" 2>/dev/null | wc -l)"
    echo; echo "### distinct SSIDs seen (beacons)"
    tshark -r "$OUT/real_wifi.pcap" -Y 'wlan.fc.type_subtype==8' \
           -T fields -e wlan.ssid 2>/dev/null | sort -u | head -30 | sed 's/^/  /'
    echo; echo "### distinct transmitters"
    echo "  $(tshark -r "$OUT/real_wifi.pcap" -T fields -e wlan.ta 2>/dev/null \
           | grep -v '^$' | sort -u | wc -l) unique MAC addresses"
} > "$OUT/summary.txt" 2>&1

TARBALL="/tmp/wd-fixture-${STAMP}.tar.gz"
tar czf "$TARBALL" -C /tmp "wd-fixture-${STAMP}"

echo
echo "=============================================================="
cat "$OUT/summary.txt" | head -25
echo "=============================================================="
echo
echo "  Bundle: $TARBALL"
echo
echo "  ⚠  This contains REAL MAC addresses and SSIDs from wherever you"
echo "     captured. Your own lab is fine. Do NOT run this at a customer"
echo "     site and share it without written permission — see ADR-20 and"
echo "     design v0.3 §12."
echo
echo "  Next: attach that .tar.gz to the Claude conversation."
