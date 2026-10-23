// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Installed as /static/iris/soniq2fa-admin-link.js and loaded by the Carbonio CE admin console (install/login-inject.sh).
// The console is a single bundle without a module registry, so the extension's administration page gets a small
// fixed button instead of a menu entry. The page itself checks the admin session; the button only links to it.
(function () {
  "use strict";
  // the console's own language (html lang, set from the admin's zimbraPrefLocale), not the browser's
  var pl = /^pl\b/i.test(document.documentElement.lang || "");
  function add() {
    if (document.getElementById("soniq2fa-admin-link")) return;
    var a = document.createElement("a");
    a.id = "soniq2fa-admin-link";
    a.href = "/service/extension/soniq2fa-admin";
    a.target = "_blank";
    a.rel = "noopener";
    a.textContent = "2FA";
    a.title = pl ? "Weryfikacja dwuetapowa — domeny i konta" : "Two-step verification — domains and accounts";
    a.setAttribute("aria-label", a.title);
    a.style.cssText = "position:fixed;right:16px;bottom:16px;z-index:2147483000;background:#2b73d2;color:#fff;" +
      "font:600 13px/1 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;padding:9px 14px;border-radius:18px;" +
      "text-decoration:none;box-shadow:0 2px 8px rgba(0,0,0,.25);opacity:.85";
    a.onmouseenter = function () { a.style.opacity = "1"; };
    a.onmouseleave = function () { a.style.opacity = ".85"; };
    document.body.appendChild(a);
  }
  if (document.body) add();
  else document.addEventListener("DOMContentLoaded", add);
})();
