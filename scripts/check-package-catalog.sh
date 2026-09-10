#!/bin/sh
# Fails when docs/agent/package-catalog.yaml and the workspace disagree.
#
# The catalog is what an agent reads before writing a shared helper, and
# platform-foundations renders it into the estate-wide index. A catalog that
# silently misses a module is worse than no catalog: it is evidence that
# nothing exists. So completeness is enforced in both directions, and the
# pointers in each entry must resolve.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
catalog="$root/docs/agent/package-catalog.yaml"
work="$root/go.work"

test -f "$catalog" || { echo "missing $catalog" >&2; exit 1; }
test -f "$work" || { echo "missing $work" >&2; exit 1; }

# Modules the workspace actually builds, one per line, sorted.
modules=$(awk '
  /^use[[:space:]]*\(/ { inside = 1; next }
  inside && /^\)/       { inside = 0 }
  inside {
    gsub(/^[[:space:]]*\.\//, ""); gsub(/[[:space:]]+$/, "")
    if ($0 != "") print
  }' "$work" | sort)

# Catalog entries: the two-space-indented keys inside the top-level
# `packages:` block, one per line, sorted.
entries=$(awk '
  /^packages:[[:space:]]*$/ { inside = 1; next }
  /^[^[:space:]#]/          { inside = 0 }
  inside && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
    gsub(/[:[:space:]]/, ""); print
  }' "$catalog" | sort)

if [ "$modules" != "$entries" ]; then
  echo "package catalog is out of step with go.work" >&2
  echo "--- go.work modules ---" >&2
  echo "$modules" >&2
  echo "--- catalog entries ---" >&2
  echo "$entries" >&2
  echo "Add the missing entry (or drop the stale one) in $catalog." >&2
  exit 1
fi

status=0

# Every working_example_path must be a real file: an entry that points at
# nothing is a claim no one can check.
awk -F'"' '/^[[:space:]]+working_example_path:/ { print $2 }' "$catalog" |
while IFS= read -r example; do
  if [ -z "$example" ] || [ ! -f "$root/$example" ]; then
    echo "working_example_path does not exist: ${example:-<empty>}" >&2
    exit 1
  fi
done || status=1

# Every related_packages name must be a catalog entry.
awk '
  /^[[:space:]]+related_packages:/ {
    line = $0
    while (match(line, /"[^"]+"/)) {
      print substr(line, RSTART + 1, RLENGTH - 2)
      line = substr(line, RSTART + RLENGTH)
    }
  }' "$catalog" |
while IFS= read -r related; do
  if ! echo "$entries" | grep -qx "$related"; then
    echo "related_packages names an unknown package: $related" >&2
    exit 1
  fi
done || status=1

if [ "$status" -ne 0 ]; then
  exit 1
fi

echo "package catalog matches go.work ($(echo "$entries" | wc -l | tr -d ' ') modules)"
