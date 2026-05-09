#!/usr/bin/env bash

set -euo pipefail

TODAY=$(date +%F)

for file in *; do
  # skip directories
  [[ -f "$file" ]] || continue

  # skip already archived files
  [[ "$file" == *.tar.gz ]] && continue

  base="${file##*/}"
  archive="${base}-${TODAY}.tar.gz"

  if tar -czf "$archive" "$file"; then
    rm -f -- "$file"
    echo "Archived and removed: $file -> $archive"
  else
    echo "Failed to archive: $file" >&2
  fi
done
