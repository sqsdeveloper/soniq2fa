#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
# SPDX-License-Identifier: GPL-2.0-or-later
# Build soniq2fa.jar against the Carbonio mailbox jars (see README), then run the self-test.
# usage: build.sh <dir with the Carbonio mailbox jars>
set -euo pipefail
JARS=${1:?usage: build.sh <dir with the Carbonio mailbox jars>}
cd "$(dirname "$0")"
rm -rf build && mkdir -p build/classes
CP=$(ls "$JARS"/*.jar | tr '\n' ':')
# Java 17 bytecode: Carbonio CE mailbox runs on Java 17 (4.20-4.23) or 21 (4.24+)
javac --release 17 -Xlint:all -cp "$CP" -d build/classes $(find src -name '*.java')
(cd src && find . -type f ! -name '*.java' | tar -cf - -T -) | tar -xf - -C build/classes
printf 'Zimbra-Extension-Class: pl.soniqsoft.soniq2fa.Soniq2faExtension\nImplementation-Version: %s\n' \
  "$(git describe --always --dirty 2>/dev/null || echo dev)" > build/MANIFEST.MF
jar cfm build/soniq2fa.jar build/MANIFEST.MF -C build/classes .

java -cp build/soniq2fa.jar pl.soniqsoft.soniq2fa.TwoFa selftest
sha256sum build/soniq2fa.jar 2>/dev/null || shasum -a 256 build/soniq2fa.jar
