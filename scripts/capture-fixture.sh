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

# ── 1. Stop the OS fighting you for the radio ────────────────────────────────
#
# THE BUG THAT PRODUCED OUR FIRST BAD FIXTURE.
#
# Setting monitor mode does not stop NetworkManager and wpa_supplicant from
# managing the interface. They keep running periodic background scans, and a
# scan sweeps the radio across every channel it knows. Our first real capture
# was declared "locked to channel 36" and had actually visited 29 frequencies
# across both bands — so every rate metric computed from it was nonsense.
#
# Silence them first, or the lock does not hold.
echo "[1/5] Releasing $IFACE from NetworkManager / wpa_supplicant…"
if command -v nmcli >/dev/null 2>&1; then
    nmcli device set "$IFACE" managed no 2>/dev/null && echo "      → NetworkManager told to ignore $IFACE"
fi
pkill -f "wpa_supplicant.*$IFACE" 2>/dev/null && echo "      → wpa_supplicant killed for $IFACE"
sleep 1

# ── 2. Monitor mode + channel lock ───────────────────────────────────────────
echo "[2/5] Setting monitor mode and locking channel $CHANNEL…"
if ! iw dev "$IFACE" info | grep -q "type monitor"; then
    ip link set "$IFACE" down
    iw dev "$IFACE" set monitor control
    ip link set "$IFACE" up
    echo "      → switched to monitor mode"
else
    echo "      → already in monitor mode"
fi

if ! iw dev "$IFACE" set channel "$CHANNEL" HT20 2>/dev/null; then
    iw dev "$IFACE" set channel "$CHANNEL" || {
        echo "      ! could not set channel $CHANNEL" >&2; exit 1; }
fi
CH_BEFORE=$(iw dev "$IFACE" info | awk '/^\tchannel/ {print $2}')
echo "      → channel now: ${CH_BEFORE:-unknown}"

# ── 3. Record metadata AFTER the radio is configured ─────────────────────────
#
# The first version of this script recorded metadata in step 1, so the file
# faithfully documented the state we were about to change — it said
# "type managed" for a capture taken in monitor mode. A record of the wrong
# moment is worse than no record, because it looks authoritative.
echo "[3/5] Recording adapter metadata (post-configuration)…"
{
    echo "### captured_at_utc"; date -u -Is
    echo; echo "### uname"; uname -a
    echo; echo "### os"; (cat /etc/os-release 2>/dev/null || true)
    echo; echo "### lsusb"; (lsusb || true)
    echo; echo "### ethtool -i $IFACE"; (ethtool -i "$IFACE" || true)
    echo; echo "### iw dev $IFACE info  (MUST show 'type monitor')"
    (iw dev "$IFACE" info || true)
    echo; echo "### iw list"; (iw list || true)
} > "$OUT/adapter-info.txt" 2>&1
echo "      → adapter-info.txt"

# ── 4. Capture ────────────────────────────────────────────────────────────────
echo "[4/5] Capturing ${DURATION}s…"
dumpcap -i "$IFACE" -B 128 -a "duration:$DURATION" \
        -w "$OUT/real_wifi.pcap" 2>&1 | tee "$OUT/dumpcap-output.txt"

# Did the lock actually hold? Ask the radio, then ask the data.
CH_AFTER=$(iw dev "$IFACE" info | awk '/^\tchannel/ {print $2}')
NFREQ=$(tshark -r "$OUT/real_wifi.pcap" -T fields -e radiotap.channel.freq 2>/dev/null \
        | grep -v '^$' | sort -u | wc -l)
{
    echo "channel_requested=$CHANNEL"
    echo "channel_before=${CH_BEFORE:-unknown}"
    echo "channel_after=${CH_AFTER:-unknown}"
    echo "distinct_frequencies_in_capture=$NFREQ"
} > "$OUT/channel-check.txt"

if [ "${NFREQ:-0}" -gt 2 ]; then
    echo
    echo "  ##############################################################"
    echo "  #  WARNING: the radio visited $NFREQ frequencies."
    echo "  #  The channel lock did NOT hold — something is still"
    echo "  #  scanning. Rate metrics from this capture are invalid."
    echo "  #  Try:  sudo airmon-ng check kill    then re-run."
    echo "  ##############################################################"
    echo
fi

# ── 4. Summarise so we know what is in it before it is shared ────────────────
echo "[5/5] Summarising…"
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
