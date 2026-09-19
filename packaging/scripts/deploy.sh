#!/usr/bin/env bash
# Health-checked symlink-swap deployment for a verified artifact directory.
set -euo pipefail

artifact_input="${1:?usage: deploy.sh ARTIFACT_DIRECTORY}"
artifact_dir="$(cd "$artifact_input" && pwd -P)"
release_root="${RELEASE_ROOT:?RELEASE_ROOT is required}"
current_link="${CURRENT_LINK:-$release_root/current}"
systemd_unit="${SYSTEMD_UNIT:?SYSTEMD_UNIT is required}"
health_url="${HEALTH_URL:?HEALTH_URL is required}"
expected_revision="${EXPECTED_REVISION:?EXPECTED_REVISION is required}"
verify_command="${VERIFY_COMMAND:?VERIFY_COMMAND is required}"
health_attempts="${HEALTH_ATTEMPTS:-30}"
health_interval="${HEALTH_INTERVAL_SECONDS:-1}"

case "$expected_revision" in
  *[!A-Za-z0-9._-]*|'')
    echo "ERROR: EXPECTED_REVISION contains unsafe path characters" >&2
    exit 2
    ;;
esac
if [ ! -x "$verify_command" ]; then
  echo "ERROR: VERIFY_COMMAND is not executable: $verify_command" >&2
  exit 2
fi

# Signature and payload verification happens before any deploy state changes.
"$verify_command" "$artifact_dir"

releases="$release_root/releases"
release="$releases/$expected_revision"
mkdir -p "$releases"
if [ -e "$release" ] || [ -L "$release" ]; then
  echo "ERROR: immutable release already exists: $release" >&2
  exit 2
fi
if [ -e "$current_link" ] && [ ! -L "$current_link" ]; then
  echo "ERROR: CURRENT_LINK exists and is not a symlink: $current_link" >&2
  exit 2
fi

previous=""
if [ -L "$current_link" ]; then
  previous="$(readlink "$current_link")"
fi

staging="$(mktemp -d "$releases/.${expected_revision}.XXXXXX")"
next_link=""
cleanup() {
  if [ -n "${next_link:-}" ] && [ -L "$next_link" ]; then
    rm -f "$next_link"
  fi
  if [ -n "${staging:-}" ] && [ -d "$staging" ]; then
    rm -rf "$staging"
  fi
}
trap cleanup EXIT

cp -pPR "$artifact_dir/." "$staging/"
# cp preserves the download directory's mode, including mktemp's 0700. Reject
# writable payloads before exposing the release, then permit service traversal.
unsafe_path="$(find "$staging" ! -type l \( -perm -0020 -o -perm -0002 \) -print -quit)"
if [ -n "$unsafe_path" ]; then
  echo "ERROR: artifact has group/world-writable permissions: $unsafe_path" >&2
  exit 2
fi
chmod 0755 "$staging"
mv "$staging" "$release"
staging=""

swap_current() {
  local target="$1"
  next_link="${current_link}.next.$$"
  ln -s "$target" "$next_link"
  if [ "$(uname -s)" = Darwin ]; then
    mv -fh "$next_link" "$current_link"
  else
    mv -Tf "$next_link" "$current_link"
  fi
  next_link=""
}

rollback() {
  if [ -n "$previous" ]; then
    swap_current "$previous"
  else
    rm -f "$current_link"
  fi
  if ! systemctl restart "$systemd_unit"; then
    echo "ROLLBACK INCOMPLETE: restored link but failed to restart $systemd_unit" >&2
    return 1
  fi
  echo "rolled back $systemd_unit to ${previous:-no active release}" >&2
}

swap_current "$release"
if ! systemctl restart "$systemd_unit"; then
  echo "ERROR: restart failed after deploying $expected_revision" >&2
  rollback || true
  exit 1
fi

body=""
for ((attempt = 1; attempt <= health_attempts; attempt++)); do
  body="$(curl --fail --silent --max-time 5 "$health_url" 2>/dev/null || true)"
  if printf '%s' "$body" | grep -Fq "$expected_revision"; then
    echo "deployed $systemd_unit at revision $expected_revision"
    exit 0
  fi
  if [ "$attempt" -lt "$health_attempts" ]; then
    sleep "$health_interval"
  fi
done

echo "ERROR: health did not report revision $expected_revision; last body: ${body:-<none>}" >&2
rollback || true
exit 1
