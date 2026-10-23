#!/bin/sh
# SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Installs soniq2fa-login.js next to the Carbonio CE login page and adds its script tag to index.html (or with
# "remove", takes both out), so the page asks for the verification code. Likewise soniq2fa-admin-link.js in the admin
# console (a button to the extension's administration page) and the code dialog on the admin console login page. Expects login.js and admin-link.js in the same directory
# as this script. Idempotent; meant to run after every package upgrade (see README, apt hook), because the
# carbonio-login-ui and carbonio-admin-ui packages replace index.html.
set -eu
INDEX=${INDEX:-/opt/zextras/web/login/index.html}
TAG='<script src="soniq2fa-login.js"></script>'
OLD='<script src="/service/extension/soniq2fa?op=login.js"></script>'
JS="$(dirname "$INDEX")/soniq2fa-login.js"
ADMIN_INDEX=${ADMIN_INDEX:-/opt/zextras/admin/iris/carbonio-admin-ui/current/index.html}
ADMIN_TAG='<script defer src="/static/iris/soniq2fa-admin-link.js"></script>'
ADMIN_JS=${ADMIN_JS:-/opt/zextras/admin/iris/soniq2fa-admin-link.js}
# rewrite in place through a temp file: keeps owner and mode, works with GNU and BSD sed
editf() { sed "$2" "$1" > "$1.soniq2fa.tmp" && cat "$1.soniq2fa.tmp" > "$1" && rm -f "$1.soniq2fa.tmp"; }
edit() { editf "$INDEX" "$1"; }

# admin console: a button to the administration page, before the console's own bundle
case "${1:-add}" in
  add)
    if [ -f "$ADMIN_INDEX" ] && [ -f "$(dirname "$0")/admin-link.js" ]; then
      cp "$(dirname "$0")/admin-link.js" "$ADMIN_JS.tmp" && chmod 644 "$ADMIN_JS.tmp" && mv "$ADMIN_JS.tmp" "$ADMIN_JS"
      if ! grep -qF "$ADMIN_TAG" "$ADMIN_INDEX"; then
        if grep -q '<script type="module" crossorigin src="/static/iris/carbonio-admin-ui/shell.mjs">' "$ADMIN_INDEX"; then
          editf "$ADMIN_INDEX" "s#<script type=\"module\" crossorigin src=\"/static/iris/carbonio-admin-ui/shell.mjs\">#$ADMIN_TAG&#"
        else
          echo "soniq2fa: unexpected $ADMIN_INDEX, not changed" >&2
        fi
      fi
    fi
    ;;
  remove)
    [ -f "$ADMIN_INDEX" ] && editf "$ADMIN_INDEX" "s#$ADMIN_TAG##"
    rm -f "$ADMIN_JS"
    ;;
esac

# admin console login: the same dialog (password, then code), without the recovery link
ADMIN_LOGIN=${ADMIN_LOGIN:-/opt/zextras/admin/login/index.html}
ADMIN_LOGIN_TAG='<script src="soniq2fa-login.js" data-admin></script>'
if [ -f "$ADMIN_LOGIN" ]; then
  case "${1:-add}" in
    add)
      cp "$(dirname "$0")/login.js" "$(dirname "$ADMIN_LOGIN")/soniq2fa-login.js.tmp" \
        && chmod 644 "$(dirname "$ADMIN_LOGIN")/soniq2fa-login.js.tmp" \
        && mv "$(dirname "$ADMIN_LOGIN")/soniq2fa-login.js.tmp" "$(dirname "$ADMIN_LOGIN")/soniq2fa-login.js"
      if ! grep -qF "$ADMIN_LOGIN_TAG" "$ADMIN_LOGIN"; then
        if grep -q '<script defer="defer" src="index.js">' "$ADMIN_LOGIN"; then
          editf "$ADMIN_LOGIN" "s#<script defer=\"defer\" src=\"index.js\">#$ADMIN_LOGIN_TAG&#"
        else
          echo "soniq2fa: unexpected $ADMIN_LOGIN, not changed" >&2
        fi
      fi
      ;;
    remove)
      editf "$ADMIN_LOGIN" "s#$ADMIN_LOGIN_TAG##"
      rm -f "$(dirname "$ADMIN_LOGIN")/soniq2fa-login.js"
      ;;
  esac
fi

[ -f "$INDEX" ] || exit 0
case "${1:-add}" in
  add)
    cp "$(dirname "$0")/login.js" "$JS.tmp" && chmod 644 "$JS.tmp" && mv "$JS.tmp" "$JS"
    if grep -qF "$OLD" "$INDEX"; then edit "s#$OLD##"; fi
    grep -qF "$TAG" "$INDEX" && exit 0
    # before the page's own bundle, so fetch is wrapped before the form uses it
    grep -q '<script defer="defer" src="index.js">' "$INDEX" || { echo "soniq2fa: unexpected $INDEX, not changed" >&2; exit 0; }
    edit "s#<script defer=\"defer\" src=\"index.js\">#$TAG&#"
    ;;
  remove)
    edit "s#$TAG##"
    edit "s#$OLD##"
    rm -f "$JS"
    ;;
esac
