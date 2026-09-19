#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

scratch="$(mktemp -d)"
scratch="$(cd "$scratch" && pwd -P)"
trap 'rm -rf "$scratch"' EXIT
chmod 0755 "$scratch"
fake_bin="$scratch/bin"
release_root="$scratch/service"
events="$scratch/events"
health_body="$scratch/health"
mkdir -p "$fake_bin" "$release_root/releases/original" "$scratch/artifact-good" "$scratch/artifact-bad"
ln -s "$release_root/releases/original" "$release_root/current"
printf '%s\n' old > "$release_root/releases/original/sample"
printf '%s\n' good > "$scratch/artifact-good/sample"
printf '%s\n' bad > "$scratch/artifact-bad/sample"
# CI downloads commonly live in mktemp's private directory. The release root
# must be normalized before restart, while payload permissions remain intact.
chmod 0700 "$scratch/artifact-good"
export DEPLOY_TEST_SERVICE_USER=''
if command -v sudo >/dev/null && sudo -n -u nobody -- true 2>/dev/null; then
  export DEPLOY_TEST_SERVICE_USER=nobody
elif [ "${CI:-}" = true ] && [ "$(uname -s)" = Linux ]; then
  echo 'Linux CI requires sudo to exercise a separate service user' >&2
  exit 1
else
  echo 'Separate-user read unavailable; directory mode is still checked' >&2
fi

cat > "$fake_bin/systemctl" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
printf 'systemctl %s\n' "$*" >> "$DEPLOY_TEST_EVENTS"
test "$(find -L "$CURRENT_LINK" -maxdepth 0 -perm 0755 -print)" = "$CURRENT_LINK"
if [ -n "$DEPLOY_TEST_SERVICE_USER" ]; then
  sudo -n -u "$DEPLOY_TEST_SERVICE_USER" -- test -r "$CURRENT_LINK/sample"
fi
SCRIPT
cat > "$fake_bin/curl" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
cat "$DEPLOY_TEST_HEALTH_BODY"
SCRIPT
cat > "$fake_bin/verify-artifact" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
test -d "$1"
printf 'verify %s\n' "$1" >> "$DEPLOY_TEST_EVENTS"
SCRIPT
chmod +x "$fake_bin/systemctl" "$fake_bin/curl" "$fake_bin/verify-artifact"

export PATH="$fake_bin:$PATH"
export DEPLOY_TEST_EVENTS="$events"
export DEPLOY_TEST_HEALTH_BODY="$health_body"
export RELEASE_ROOT="$release_root"
export CURRENT_LINK="$release_root/current"
export SYSTEMD_UNIT="sample.service"
export HEALTH_URL="http://127.0.0.1:8080/api/health"
export VERIFY_COMMAND="$fake_bin/verify-artifact"
export HEALTH_ATTEMPTS=1
export HEALTH_INTERVAL_SECONDS=0

printf '{"revision":"good-revision"}\n' > "$health_body"
EXPECTED_REVISION=good-revision bash scripts/deploy.sh "$scratch/artifact-good"
good_target="$release_root/releases/good-revision"
if [ "$(readlink "$release_root/current")" != "$good_target" ]; then
  echo "successful deploy did not swap current symlink" >&2
  exit 1
fi
test "$(cat "$release_root/current/sample")" = good
test "$(find "$scratch/artifact-good" -maxdepth 0 -perm 0700 -print)" = "$scratch/artifact-good"
grep -Fx "verify $scratch/artifact-good" "$events" >/dev/null
grep -Fx "systemctl restart sample.service" "$events" >/dev/null

printf '{"revision":"still-good"}\n' > "$health_body"
if EXPECTED_REVISION=bad-revision bash scripts/deploy.sh "$scratch/artifact-bad"; then
  echo "deploy accepted a mismatched health revision" >&2
  exit 1
fi
if [ "$(readlink "$release_root/current")" != "$good_target" ]; then
  echo "failed deploy did not roll current back to the previous release" >&2
  exit 1
fi
test "$(cat "$release_root/current/sample")" = good
if [ "$(grep -Fc 'systemctl restart sample.service' "$events")" -ne 3 ]; then
  echo "deploy did not restart once on success and twice on failed-health rollback" >&2
  exit 1
fi

mkdir -p "$scratch/artifact-unsafe/nested"
printf '%s\n' unsafe > "$scratch/artifact-unsafe/sample"
for fixture in 'sample 0664' 'nested 0775' '. 0777' 'sample 0646'; do
  read -r path mode <<< "$fixture"
  chmod "$mode" "$scratch/artifact-unsafe/$path"
  restarts_before="$(grep -Fc 'systemctl restart' "$events")"
  if EXPECTED_REVISION=unsafe-revision bash scripts/deploy.sh "$scratch/artifact-unsafe"; then
    echo "deploy accepted writable artifact mode $fixture" >&2
    exit 1
  fi
  test ! -e "$release_root/releases/unsafe-revision"
  test "$(readlink "$release_root/current")" = "$good_target"
  test "$(grep -Fc 'systemctl restart' "$events")" = "$restarts_before"
  chmod 0755 "$scratch/artifact-unsafe" "$scratch/artifact-unsafe/nested"
  chmod 0644 "$scratch/artifact-unsafe/sample"
done

echo "deploy traversal, writable-mode rejection, symlink swap and health rollback verified"
