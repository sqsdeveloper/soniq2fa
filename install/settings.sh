#!/bin/bash
# SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Installs (default) or removes ("remove") the webmail Settings entry. Run as root from the install/ directory.
# Carbonio web packages rebuild components.json from every iris/*/*/component.json on installation, so the module
# stays registered after upgrades; this script rebuilds it the same way.
set -euo pipefail
IRIS=/opt/zextras/web/iris
DIR=$IRIS/soniq2fa-ui
if [ "${1:-}" = remove ]; then
  rm -rf "$DIR"
else
  install -d -m 755 "$DIR/1"
  install -m 644 "$(dirname "$0")/settings/component.json" "$(dirname "$0")/settings/app.js" "$DIR/1/"
fi
chown -R zextras:zextras "$IRIS/soniq2fa-ui" 2>/dev/null || true
find "$IRIS" -maxdepth 3 -mindepth 3 -type f -name component.json -printf '%T@ %p\n' | sort -rn |
  awk '{ n = split($2, path, "/"); if (!seen[path[6]]++) print $2 }' |
  xargs jq -s '{"components":.}' > "$IRIS/components.json.new"
mv "$IRIS/components.json.new" "$IRIS/components.json"
jq -r '.components[].name' "$IRIS/components.json"
