#!/usr/bin/env bash
set -euo pipefail

# Sync official ProjectDiscovery nuclei-templates for offline / local ARTEX runs.
# Usage:
#   ./scripts/sync-nuclei-templates.sh [TARGET_DIR]
# Default target dir: ./data/nuclei-templates

VERSION="${NUCLEI_TEMPLATES_VERSION:-v10.1.3}"
DEST="${1:-${ARTEX_NUCLEI_TEMPLATES_DIR:-./data/nuclei-templates}}"

mkdir -p "$DEST"
TMP_TGZ="$(mktemp /tmp/nuclei-templates.XXXXXX.tar.gz)"
trap 'rm -f "$TMP_TGZ"' EXIT

URL="https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${VERSION}.tar.gz"
echo "[sync-nuclei-templates] Downloading ${URL} ..."
curl -fsSL "$URL" -o "$TMP_TGZ"

echo "[sync-nuclei-templates] Extracting to ${DEST} ..."
tar -xzf "$TMP_TGZ" -C "$DEST" --strip-components=1
rm -rf "${DEST}/.git" "${DEST}/.github"

COUNT="$(find "$DEST" -type f -name '*.yaml' | wc -l | tr -d ' ')"
echo "[sync-nuclei-templates] Done: ${COUNT} YAML templates ready in ${DEST}"
echo "[sync-nuclei-templates] ARTEX auto-detects ./data/nuclei-templates, ~/nuclei-templates, or ARTEX_NUCLEI_TEMPLATES_DIR=${DEST}"
