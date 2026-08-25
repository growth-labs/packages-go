#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

scratch="$(mktemp -d)"
scratch="$(cd "$scratch" && pwd -P)"
trap 'rm -rf "$scratch"' EXIT
fake_bin="$scratch/bin"
release_root="$scratch/service"
events="$scratch/events"
health_body="$scratch/health"
mkdir -p "$fake_bin" "$release_root/releases/original" "$scratch/artifact-good" "$scratch/artifact-bad"
ln -s "$release_root/releases/original" "$release_root/current"
printf '%s\n' old > "$release_root/releases/original/sample"
printf '%s\n' good > "$scratch/artifact-good/sample"
printf '%s\n' bad > "$scratch/artifact-bad/sample"

cat > "$fake_bin/systemctl" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
printf 'systemctl %s\n' "$*" >> "$DEPLOY_TEST_EVENTS"
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

echo "deploy symlink swap and health rollback verified"
