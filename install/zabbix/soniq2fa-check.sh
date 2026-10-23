#!/bin/sh
# SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Zabbix agent check for soniq2fa.
#   soniq2fa-check.sh ext <public host name>  1 = extension answers, 0 = mailbox up but extension missing (404),
#                                             -1 = mailbox not answering (other alerts cover that)
#   soniq2fa-check.sh login                   1 = all three pages carry their script (webmail login, admin console login,
#                                             admin console), 0 = a tag or file is missing (a package upgrade replaced
#                                             index.html and the apt hook did not run)
#   soniq2fa-check.sh sms                     1 = SMS gateway file readable by zextras, 0 = present but unreadable
#                                             (SMS hidden for everyone), 2 = no file (SMS not configured)
# A missing extension on a domain with custom:soniq2fa means nobody in that domain can sign in.
INDEX=${INDEX:-/opt/zextras/web/login/index.html}
case "${1:-}" in
  ext)
    out=$(curl -sk -m 10 -w '\n%{http_code}' -H "Host: ${2:-localhost}" \
      'https://127.0.0.1/service/extension/soniq2fa?op=domain&name=example.com') || { echo -1; exit 0; }
    code=$(printf '%s' "$out" | tail -n1)
    if [ "$code" = 200 ] && printf '%s' "$out" | grep -q '"twoFactor"'; then echo 1
    elif [ "$code" = 404 ]; then echo 0
    else echo -1; fi
    ;;
  login)
    ADMIN_LOGIN=${ADMIN_LOGIN:-/opt/zextras/admin/login/index.html}
    ADMIN_INDEX=${ADMIN_INDEX:-/opt/zextras/admin/iris/carbonio-admin-ui/current/index.html}
    if grep -qF 'soniq2fa-login.js' "$INDEX" 2>/dev/null && [ -f "$(dirname "$INDEX")/soniq2fa-login.js" ] \
      && grep -qF 'soniq2fa-login.js' "$ADMIN_LOGIN" 2>/dev/null && [ -f "$(dirname "$ADMIN_LOGIN")/soniq2fa-login.js" ] \
      && grep -qF 'soniq2fa-admin-link.js' "$ADMIN_INDEX" 2>/dev/null && [ -f /opt/zextras/admin/iris/soniq2fa-admin-link.js ]
    then echo 1; else echo 0; fi
    ;;
  sms)
    F=/opt/zextras/lib/ext/soniq2fa/soniq2fa.properties
    if [ ! -e "$F" ]; then echo 2
    else
      # the agent runs as zabbix: judge by owner, group and mode instead of reading as zextras
      set -- $(stat -c '%U %G %a' "$F")
      u=$(printf '%s' "$3" | rev | cut -c3) g=$(printf '%s' "$3" | rev | cut -c2)
      if { [ "$1" = zextras ] && [ $((u & 4)) -ne 0 ]; } || { [ "$2" = zextras ] && [ $((g & 4)) -ne 0 ]; }
      then echo 1; else echo 0; fi
    fi
    ;;
  *) echo -1 ;;
esac
