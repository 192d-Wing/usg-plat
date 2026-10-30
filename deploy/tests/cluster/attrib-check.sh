#!/bin/sh
# Attribution checker for the cluster/HA tests (plan §1.3, §8.2).
#
# Merges the audit logs of every node (plus the SIEM copy; duplicates are
# collapsed by observer + event.sequence + @timestamp), orders them by @timestamp and
# asserts:
#   1. no port block (source.nat.ip, port_start..port_end) is held by two
#      observers at once: an interval opens at nat_port_block_allocate or
#      nat_port_block_adopt and closes at nat_port_block_release, at an adopt
#      of the same block by another observer, or at cluster_slice_acquire of
#      the enclosing slice by another observer;
#   2. no block is attributed to two subscribers at once, and an adopt never
#      changes the subscriber;
#   3. no block is allocated by an observer while another observer holds the
#      enclosing slice (per cluster_slice_acquire/cluster_slice_release);
#   (a service_start of an observer closes all of its intervals: a crash
#   writes no release record, POAM-009);
#   4. with -p, every translated packet seen on the edge (lines
#      "<ISO-8601 UTC> <v4> <port>") falls into a block that was allocated or
#      adopted before it (adopt is logged before use).
#
# Usage: attrib-check.sh [-p packets.txt [-t skew-ms]] audit.jsonl [audit.jsonl ...]
# -t: packets are stamped by the capturing host (the edge), records by the
# node; a packet up to skew-ms before its record is accepted (cross-host
# clock error; the same-clock order is verified on the node itself).
# Exit: 0 no violation; 1 violations (listed on stdout); 2 usage/input error.
#
# Timestamps from different nodes are compared directly: the nodes must be
# NTP-synchronized (chrony in the Lima VMs).
#
# COMPLIANCE MAPPING:
# - NIST 800-53: AU-3 (Content of Audit Records), AU-10 (Non-repudiation)
# - RFC 6888 REQ-12 - attribution of the translated address and port
set -eu

PKTS=
SKEW_US=0
while getopts p:t: opt; do
    case "$opt" in
        p) PKTS=$OPTARG ;;
        t) case $OPTARG in *[!0-9]* | '') echo "attrib-check: -t takes milliseconds" >&2; exit 2 ;; esac
           SKEW_US=$((OPTARG * 1000)) ;;
        *) echo "usage: attrib-check.sh [-p packets.txt] audit.jsonl..." >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || { echo "usage: attrib-check.sh [-p packets.txt] audit.jsonl..." >&2; exit 2; }
for f in "$@" ${PKTS:+"$PKTS"}; do
    [ -r "$f" ] || { echo "attrib-check: cannot read $f" >&2; exit 2; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Stage 1: one normalized record per relevant event:
#   ts|seq|observer|action|natip|port_start|port_end|subscriber|slice
awk '
function esc(k) { gsub(/\./, "\\.", k); return k }
function jstr(k,   p) {
    p = "\"" esc(k) "\":\"[^\"]*\""
    if (match($0, p)) return substr($0, RSTART + length(k) + 4, RLENGTH - length(k) - 5)
    return ""
}
function jnum(k,   p) {
    p = "\"" esc(k) "\":-?[0-9]+"
    if (match($0, p)) return substr($0, RSTART + length(k) + 3, RLENGTH - length(k) - 3)
    return ""
}
{
    a = jstr("event.action")
    if (a != "nat_port_block_allocate" && a != "nat_port_block_release" && a != "nat_port_block_adopt" &&
        a != "cluster_slice_acquire" && a != "cluster_slice_release" && a != "service_start") next
    if (jstr("event.outcome") == "failure") next
    obs = jstr("observer.name"); seq = jnum("event.sequence")
    # observer + sequence + timestamp: a node whose audit files were removed
    # (f12 archives them) restarts its sequence, so seq alone can repeat.
    id = (seq == "") ? $0 : obs "|" seq "|" jstr("@timestamp")
    if (id in seen) next
    seen[id] = 1
    printf "%s|%s|%s|%s|%s|%s|%s|%s|%s\n", jstr("@timestamp"), seq, obs, a, jstr("source.nat.ip"),
        jnum("plat.nat.port_start"), jnum("plat.nat.port_end"), jstr("plat.subscriber.prefix"), jstr("cluster.slice")
}' "$@" >"$WORK/events"
if [ -n "$PKTS" ]; then
    # Shift packet times forward by the skew allowance (ISO-8601 UTC, µs).
    awk -v sk="$SKEW_US" 'NF >= 3 {
        t = $1
        if (sk > 0) {
            split(substr(t, 12, 15), h, /[:.Z]/)
            us = ((h[1] * 60 + h[2]) * 60 + h[3]) * 1000000 + h[4] + sk
            if (us < 86400000000) t = sprintf("%s%02d:%02d:%02d.%06dZ", substr(t, 1, 11), int(us / 3600000000),
                int(us / 60000000) % 60, int(us / 1000000) % 60, us % 1000000)
        }
        printf "%s||edge|pkt|%s|%s|%s||\n", t, $2, $3, $3 }' "$PKTS" >>"$WORK/events"
fi

# Stage 2: time order (ISO-8601 UTC with fixed precision sorts lexically;
# within one timestamp, by sequence).
sort -t'|' -k1,1 -k2,2n "$WORK/events" >"$WORK/sorted"

# Stage 3: interval bookkeeping.
awk -F'|' '
function ip2n(ip,   o) { split(ip, o, "."); return ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4] }
function inslice(ip, cidr,   c, len, size) {
    split(cidr, c, "/"); len = c[2] + 0; size = 2 ^ (32 - len)
    return int(ip2n(ip) / size) == int(ip2n(c[1]) / size)
}
function bad(msg) { nbad++; print "VIOLATION " $1 " " msg }
{
    ts = $1; obs = $3; act = $4; key = $5 "|" $6 "|" $7; sub_ = $8
    if (act == "nat_port_block_allocate" || act == "nat_port_block_adopt") {
        if (act == "nat_port_block_allocate") {
            nalloc++
            for (s in owner) if (owner[s] != "" && owner[s] != obs && inslice($5, s))
                bad("block " key " allocated by " obs " while slice " s " is held by " owner[s])
        } else nadopt++
        for (k in open) {
            split(k, p, SUBSEP)
            if (p[1] != key) continue
            if (p[2] == obs) {
                if (open[k] != sub_) bad("block " key " on " obs " attributed to " open[k] " and " sub_)
            } else if (act == "nat_port_block_adopt") {
                if (open[k] != sub_) bad("block " key " adopted by " obs " for " sub_ " but held by " p[2] " for " open[k])
                delete open[k]
            } else {
                bad("block " key " allocated by " obs " for " sub_ " while held by " p[2] " for " open[k])
            }
        }
        open[key, obs] = sub_
    } else if (act == "nat_port_block_release") {
        nrel++
        delete open[key, obs]
    } else if (act == "cluster_slice_acquire") {
        owner[$9] = obs
        for (k in open) {
            split(k, p, SUBSEP); split(p[1], b, "|")
            if (p[2] != obs && inslice(b[1], $9)) delete open[k]
        }
    } else if (act == "service_start") {
        # A crash writes no release (POAM-009, SIEM_LOGGING.md): a restart
        # of the observer ends every block and slice it held.
        for (k in open) { split(k, p, SUBSEP); if (p[2] == obs) delete open[k] }
        for (s in owner) if (owner[s] == obs) owner[s] = ""
    } else if (act == "cluster_slice_release") {
        if (owner[$9] == obs) owner[$9] = ""
    } else if (act == "pkt") {
        npkt++; hit = 0
        for (k in open) {
            split(k, p, SUBSEP); split(p[1], b, "|")
            if (b[1] == $5 && b[2] + 0 <= $6 + 0 && $6 + 0 <= b[3] + 0) { hit = 1; break }
        }
        if (!hit) bad("packet from " $5 ":" $6 " before any allocate/adopt of its block")
    }
}
END {
    printf "attrib-check: %d allocate, %d adopt, %d release, %d packets, %d violation(s)\n",
        nalloc, nadopt, nrel, npkt, nbad
    exit (nbad > 0)
}' "$WORK/sorted"
