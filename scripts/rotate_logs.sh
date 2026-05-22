#!/usr/bin/env bash
set -euo pipefail
find logs -name '*.log' -o -name '*.jsonl' | while read -r f; do
  [ -s "$f" ] && cp "$f" "$f.$(date +%Y%m%d%H%M%S)" && : > "$f"
done
find logs -type f -mtime +30 -delete
