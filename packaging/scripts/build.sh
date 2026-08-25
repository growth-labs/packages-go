#!/usr/bin/env bash
# Adapted from fulcrum-labs/foundry@e9a312008010218b06dabafca6cb33fdcb897cb0.
set -euo pipefail

cd "$(dirname "$0")/.."

package_main="${PACKAGE_MAIN:?PACKAGE_MAIN is required}"
package_name="${PACKAGE_NAME:?PACKAGE_NAME is required}"
version="${PACKAGE_VERSION:-development}"
revision="${PACKAGE_REVISION:-$(git rev-parse HEAD)}"
targets="${BUILD_TARGETS:-darwin-arm64 linux-amd64}"
dist_dir="${DIST_DIR:-dist}"
ldflags="-X github.com/growth-labs/packages-go/packaging/provenance.Version=${version} -X github.com/growth-labs/packages-go/packaging/provenance.Revision=${revision}"

mkdir -p "$dist_dir"
built=()
for target in $targets; do
  goos="${target%%-*}"
  goarch="${target##*-}"
  output="${package_name}-${target}"
  echo "building ${output}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "$ldflags" -o "$dist_dir/$output" "$package_main"
  built+=("$output")
done

if [ "${#built[@]}" -eq 0 ]; then
  echo "BUILD_TARGETS selected nothing to build" >&2
  exit 2
fi

(
  cd "$dist_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${built[@]}" > SHA256SUMS
  else
    shasum -a 256 "${built[@]}" > SHA256SUMS
  fi
)

echo "built ${#built[@]} binaries at revision ${revision}"
