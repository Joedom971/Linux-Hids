#!/bin/bash
# ============================================================================
# file_integrity_events.sh — Real-time file-tampering watcher (Stage 3b)
# ============================================================================
# file_integrity.sh hashes every critical file on a timer (slow, can miss
# short-lived modifications between scans). This module uses inotify to
# fire an alert the instant a watched file is modified, replaced, moved,
# or deleted. It runs in parallel with the periodic hasher — the periodic
# scan stays as a safety net in case inotifywait wasn't running when a
# change occurred.
#
# Why watch parent directories, not the files directly?
#   Atomic editors (sed -i, install(1), cp --backup) write a new file and
#   rename it over the original. That changes the inode, which invalidates
#   any watch attached to the old inode. Watching the parent dir and
#   filtering by filename catches the replace case correctly.
#
# Streaming consumer: SIGTERM terminates the pipeline and exits.
# ============================================================================

HIDS_DIR="${HIDS_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

source "$HIDS_DIR/modules/alerting.sh"
source "$HIDS_DIR/config/file_integrity.conf"

RAW_LOG="$HIDS_DIR/logs/raw_events.log"

if ! command -v inotifywait &>/dev/null; then
  alert "WARNING" "file_integrity_events" \
    "inotifywait not installed; install inotify-tools. Event stream disabled."
  exit 0
fi

# Build parent-dir set + watched-file filter. Associative arrays dedupe dirs.
declare -A DIRS
declare -A WATCHED
for f in "${CRITICAL_FILES[@]}"; do
  [[ -e "$f" ]] || continue   # skip files that don't exist on this host
  DIRS["$(dirname "$f")"]=1
  WATCHED["$f"]=1
done

if (( ${#DIRS[@]} == 0 )); then
  alert "WARNING" "file_integrity_events" \
    "no critical files present on host — nothing to watch"
  exit 0
fi

trap 'exit 0' TERM INT

# -m : monitor (keep running); -q : quiet; per-event format with | separator
inotifywait -m -q \
  -e modify -e attrib -e moved_to -e create -e delete -e move_self -e delete_self \
  --format '%w|%f|%e' "${!DIRS[@]}" 2>/dev/null \
| while IFS='|' read -r dir filename event; do
    # inotifywait emits `%w` as the watched dir with trailing slash
    path="${dir%/}/$filename"

    # Filter: only alert on files we care about
    [[ -n "${WATCHED[$path]:-}" ]] || continue

    alert "CRITICAL" "file_integrity" "inotify[$event] $path"
    echo "$(date -Iseconds)|file_integrity|inotify|$path|event=$event" >> "$RAW_LOG"
  done
