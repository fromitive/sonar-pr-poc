#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
command -v trivy >/dev/null
command -v python3 >/dev/null
test -s gradle.lockfile
mkdir -p .trivy-poc
rm -f .trivy-poc/trivy.json .trivy-poc/sonar.json
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp gradle.lockfile "$stage/gradle.lockfile"
# Only scan the lockfile, not the scanner's own dependencies or build artifacts.
# Include dev packages for this PoC so every locked package can be validated.
trivy fs --scanners vuln --include-dev-deps --list-all-pkgs \
  --ignorefile /dev/null --exit-code 0 --format json \
  --output "$PWD/.trivy-poc/trivy.json" "$stage"
python3 .sonar-pr/trivy-to-sonar.py .trivy-poc/trivy.json gradle.lockfile .trivy-poc/sonar.json
