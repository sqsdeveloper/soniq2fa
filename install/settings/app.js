// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Carbonio web module (installed by install/settings.sh): adds "Two-step verification" to webmail Settings, showing
// the self-service page of the extension. The entry appears only for accounts that may turn 2FA on or already have it.
// When 2FA is required and not set up yet, the page opens over webmail and stays until 2FA is on.
(function () {
  "use strict";
  var NAME = "soniq2fa-ui";
  var BASE = "/service/extension/soniq2fa";
  var React = __ZAPP_SHARED_LIBRARIES__.react;
  var shell = __ZAPP_SHARED_LIBRARIES__["@zextras/carbonio-shell-ui"][NAME];

  var label = "Two-step verification";

  function View() {
    return React.createElement("iframe", {
      src: BASE, title: label,
      style: { border: 0, width: "100%", height: "100%", minHeight: "80vh", display: "block" }
    });
  }

  function json(op) {
    return fetch(BASE + "?op=" + op, { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { if (!r.ok) throw new Error(op); return r.json(); });
  }

  // Full-window setup: the page in a frame, a bar with the explanation and a button that unlocks once 2FA is on
  // (the page shows the backup codes after enrolment, so the user leaves when ready, not automatically).
  function requireSetup(t) {
    var overlay = document.createElement("div");
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.style.cssText = "position:fixed;inset:0;background:#fff;z-index:2147483647;display:flex;flex-direction:column;" +
      "font:15px/1.5 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
    var bar = document.createElement("div");
    bar.style.cssText = "display:flex;gap:16px;align-items:center;justify-content:space-between;padding:12px 24px;" +
      "border-bottom:1px solid #e5e7eb;background:#f9fafb;color:#333";
    var text = document.createElement("div");
    var title = document.createElement("strong");
    title.textContent = t("required.title");
    var intro = document.createElement("div");
    intro.textContent = t("required.intro");
    intro.style.cssText = "font-size:14px;color:#6b7280";
    text.appendChild(title);
    text.appendChild(intro);
    var done = document.createElement("button");
    done.textContent = t("required.continue");
    done.disabled = true;
    done.style.cssText = "font:inherit;background:#2b73d2;color:#fff;border:0;border-radius:6px;padding:8px 16px;" +
      "cursor:pointer;white-space:nowrap";
    var frame = document.createElement("iframe");
    frame.src = BASE;
    frame.title = label;
    frame.style.cssText = "border:0;flex:1;width:100%";
    bar.appendChild(text);
    bar.appendChild(done);
    overlay.appendChild(bar);
    overlay.appendChild(frame);
    document.body.appendChild(overlay);
    done.style.opacity = ".5";
    var timer = setInterval(function () {
      json("state").then(function (s) {
        if (!s.enabled) return;
        clearInterval(timer);
        done.disabled = false;
        done.style.opacity = "1";
      }).catch(function () {});
    }, 3000);
    done.onclick = function () { if (!done.disabled) overlay.remove(); };
  }

  function App() {
    React.useEffect(function () {
      Promise.all([json("state"), json("i18n")]).then(function (res) {
        var s = res[0], i = res[1];
        if (!s.enabled && (s.reason === "not_enabled" || s.reason === "not_offered")) return;
        var t = function (k) { return (i.messages && i.messages[k]) || (i.fallback && i.fallback[k]) || k; };
        label = t("title");
        shell.addSettingsView({ route: "soniq2fa", label: label, component: View });
        if (s.required && !s.enabled && s.available) requireSetup(t);
      }).catch(function () {});
    }, []);
    return null;
  }

  window.__ZAPP_HMR_EXPORT__[NAME](App);
})();
