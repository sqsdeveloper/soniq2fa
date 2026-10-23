// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Installed next to the Carbonio CE login pages (webmail and admin console) as /static/login/soniq2fa-login.js (install/login-inject.sh) and loaded
// by index.html before the page's own bundle. Wraps window.fetch for the login form's SOAP requests:
//  - AuthRequest / ChangePasswordRequest for a domain that uses soniq2fa: asks for the code in a dialog and appends it
//    to the password. The server answers a wrong password with AUTH_FAILED and the right one without a code with
//    TWO_FACTOR_AUTH_REQUIRED ("codeRequired" in the domain answer), so the dialog opens only after the right password;
//    a wrong code (TWO_FACTOR_AUTH_FAILED) asks again. The dialog can have the code sent by SMS or to the recovery address (with the password typed in the
//    form; the server sends only after checking it). The dialog opens before the request when this browser remembers the user as enrolled (set by
//    the self-service page and by every sign-in with a code), otherwise only after the password alone was refused,
//    so users without 2FA never see it. The server answers the same for every account; the hint stays local;
//  - Carbonio's own password recovery (RecoverAccountRequest) refused for a domain that uses soniq2fa: it is turned off
//    for accounts with 2FA, so a dialog offers the extension's recovery instead, with the address filled in;
//  - every AuthRequest: if the browser still holds an invalidated session cookie, the mailbox refuses the request before
//    checking the password ("auth credentials have expired") — the cookie is cleared through Carbonio's /logout and the
//    request is sent once more;
//  - a POST after the code dialog may hit a connection the server closed while idle (Safari then fails with
//    "Load failed" without retrying): a GET first, and one retry on a network error.
// The login form itself is not modified. Without the extension the domain check fails and the page logs in as usual.
(function () {
  "use strict";
  var BASE = "/service/extension/soniq2fa";
  var realFetch = window.fetch.bind(window);
  var bundle = {}, fallback = {}, domains = {};
  // loaded by the admin console login page too (data-admin): no self-service recovery link there
  var adminLogin = !!(document.currentScript && document.currentScript.hasAttribute("data-admin"));

  realFetch(BASE + "?op=i18n", { credentials: "same-origin" })
    .then(function (r) { return r.json(); })
    .then(function (i) {
      bundle = i.messages || {};
      fallback = i.fallback || {};
      if (document.body) recoveryLink();
      else document.addEventListener("DOMContentLoaded", recoveryLink);
    })
    .catch(function () {});

  // Texts added after the extension was deployed: used until the jar with them is in place.
  var BUILTIN = /^pl\b/i.test(navigator.language || "") ? {
    "login.recoverTitle": "Odzyskiwanie hasła",
    "login.recoverIntro": "Wbudowane odzyskiwanie Carbonio jest niedostępne dla tego konta. Jeśli masz weryfikację dwuetapową, odzyskasz hasło kodem z adresu zapasowego i kodem z aplikacji.",
    "login.recoverGo": "Odzyskaj hasło", "login.cancel": "Anuluj" } : {
    "login.recoverTitle": "Password recovery",
    "login.recoverIntro": "Carbonio's built-in recovery is not available for this account. If you use two-step verification, recover your password with a code from your recovery address and the code from your app.",
    "login.recoverGo": "Recover password", "login.cancel": "Cancel" };

  function t(key) { return bundle[key] || fallback[key] || BUILTIN[key] || key; }

  // {"twoFactor":bool,"sms":bool} of the user's domain; "sms" is absent before the jar with login codes is deployed.
  function domainInfo(user) {
    var d = String(user || "").split("@")[1];
    if (!d) return Promise.resolve({});
    d = d.toLowerCase();
    if (!(d in domains)) {
      domains[d] = realFetch(BASE + "?op=domain&name=" + encodeURIComponent(d), { credentials: "same-origin", cache: "no-store" })
        .then(function (r) { return r.ok ? r.json() : {}; })
        .catch(function () { return {}; });
    }
    return domains[d];
  }

  function domainUsesTwoFactor(user) {
    return domainInfo(user).then(function (j) { return j.twoFactor === true; });
  }

  // Asks the server to send a login code by SMS or to the recovery address. The answer is the same whatever happens.
  function sendCode(user, password, channel) {
    var body = new URLSearchParams({ op: "send", account: user, password: password, channel: channel });
    return realFetch("/service/extension/soniq2fa-recover", { method: "POST", credentials: "same-origin",
      headers: { "X-Soniq2fa": "1" }, body: body }).catch(function () {});
  }

  function remembered(user) {
    try { return localStorage.getItem("soniq2fa:" + user.toLowerCase()) === "1"; } catch (e) { return false; }
  }

  function remember(user, on) {
    try {
      if (on) localStorage.setItem("soniq2fa:" + user.toLowerCase(), "1");
      else localStorage.removeItem("soniq2fa:" + user.toLowerCase());
    } catch (e) {}
  }

  // Resolves with the code typed by the user, "" for "sign in without a code", or null when cancelled.
  // mode: "ask" before the first attempt (offers "sign in without a code"); "need" the server confirmed the password and
  // wants the code; "retry" an older server refused the password alone (it cannot tell why). error: shown in red.
  // sender: {user, password, info} — links that send the code by SMS (when the server has a gateway) or by e-mail.
  function askCode(mode, sender, error) {
    var retry = mode !== "ask";
    return new Promise(function (resolve) {
      var overlay = document.createElement("div");
      overlay.setAttribute("role", "dialog");
      overlay.setAttribute("aria-modal", "true");
      overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,.45);display:flex;align-items:center;" +
        "justify-content:center;z-index:2147483647;font:15px/1.5 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
      var box = document.createElement("form");
      box.style.cssText = "background:#fff;color:#333;border-radius:8px;padding:24px;width:min(92vw,380px);" +
        "box-shadow:0 8px 32px rgba(0,0,0,.25)";
      function el(tag, text, css) {
        var e = document.createElement(tag);
        if (text) e.textContent = text;
        if (css) e.style.cssText = css;
        return e;
      }
      var title = el("h2", t("login.title"), "font-size:18px;margin:0 0 8px");
      var intro = el("p", t(mode === "retry" ? "login.retryIntro" : "login.intro"), "margin:0 0 16px;color:#6b7280;font-size:14px");
      var problem = error ? el("p", error, "margin:0 0 12px;color:#c0392b;font-size:14px") : null;
      if (problem) problem.setAttribute("role", "alert");
      var input = el("input", "", "font:inherit;font-size:20px;letter-spacing:2px;text-align:center;width:100%;" +
        "box-sizing:border-box;padding:8px 10px;border:1px solid #c9ced6;border-radius:6px");
      input.autocomplete = "one-time-code";
      input.maxLength = 11;
      input.setAttribute("aria-label", t("login.code"));
      input.placeholder = "000000";
      var ok = el("button", t("login.submit"), "font:inherit;background:#2b73d2;color:#fff;border:0;border-radius:6px;" +
        "padding:8px 16px;cursor:pointer;margin-right:8px");
      ok.type = "submit";
      var cancel = el("button", t("login.cancel"), "font:inherit;background:#fff;color:#2b73d2;border:1px solid #2b73d2;" +
        "border-radius:6px;padding:8px 16px;cursor:pointer");
      cancel.type = "button";
      var row = el("div", "", "margin:16px 0 12px");
      row.appendChild(ok);
      row.appendChild(cancel);
      var skip = el("a", t("login.noTwoFactor"), "font-size:13px;color:#2b73d2;cursor:pointer");
      skip.href = "#";
      var hint = el("p", t("login.hint"), "margin:12px 0 0;color:#6b7280;font-size:13px");
      var channels = null;
      if (sender && sender.info && "sms" in sender.info) {
        channels = el("p", "", "margin:12px 0 0;font-size:13px");
        var status = el("span", "", "display:block;margin-top:6px;color:#1f8a4c");
        status.setAttribute("role", "status");
        [sender.info.sms ? "sms" : null, "email"].forEach(function (ch) {
          if (!ch) return;
          var a = el("a", t(ch === "sms" ? "login.sendSms" : "login.sendEmail"), "color:#2b73d2;cursor:pointer;margin-right:16px");
          a.href = "#";
          a.onclick = function (e) {
            e.preventDefault();
            if (!sender.password) { status.textContent = t("login.sendNeedsPassword"); return; }
            // the server sends at most one login code a minute per account
            channels.querySelectorAll("a").forEach(function (l) { l.style.pointerEvents = "none"; l.style.opacity = ".5"; });
            setTimeout(function () {
              channels.querySelectorAll("a").forEach(function (l) { l.style.pointerEvents = ""; l.style.opacity = ""; });
            }, 60000);
            sendCode(sender.user, sender.password, ch).then(function () {
              status.textContent = t("login.sent") + " " + t("login.wait");
              input.focus();
            });
          };
          channels.appendChild(a);
        });
        channels.appendChild(status);
      }
      [title, intro, problem, input, row, channels, retry ? null : skip, hint].forEach(function (n) { if (n) box.appendChild(n); });
      overlay.appendChild(box);
      document.body.appendChild(overlay);
      input.focus();
      function done(v) { overlay.remove(); resolve(v); }
      box.onsubmit = function (e) { e.preventDefault(); var v = input.value.replace(/\s+/g, ""); if (v) done(v); else input.focus(); };
      cancel.onclick = function () { done(null); };
      skip.onclick = function (e) { e.preventDefault(); done(""); };
      overlay.addEventListener("keydown", function (e) { if (e.key === "Escape") done(null); });
    });
  }

  // POST with a fresh connection, one retry on a network error.
  function post(input, init) {
    return realFetch(BASE + "?op=domain&name=warmup", { credentials: "same-origin", cache: "no-store" })
      .catch(function () {})
      .then(function () { return realFetch(input, init); })
      .catch(function (e) {
        if (e && e.name === "TypeError") return realFetch(input, init);
        throw e;
      });
  }

  // Refused before authentication because of an invalidated session cookie: clear it and send once more.
  function send(input, init) {
    return post(input, init).then(function (res) {
      if (res.ok) return res;
      return res.clone().text().then(function (body) {
        if (!/auth credentials have expired|AUTH_EXPIRED/.test(body)) return res;
        return realFetch("/logout", { credentials: "same-origin", redirect: "manual", cache: "no-store" })
          .catch(function () {})
          .then(function () { return post(input, init); });
      }, function () { return res; });
    });
  }

  // What the login form shows for a refused login, used when the dialog is cancelled.
  function cancelled() {
    var body = { Body: { Fault: { Code: { Value: "soap:Sender" }, Reason: { Text: "authentication failed" },
      Detail: { Error: { Code: "account.AUTH_FAILED", _jsns: "urn:zimbra" } } } } };
    return new Response(JSON.stringify(body), { status: 500, headers: { "Content-Type": "application/json" } });
  }

  // Link to the self-service password recovery (accounts with 2FA), under the login form.
  function recoveryLink() {
    if (adminLogin || document.getElementById("soniq2fa-recover")) return;
    var a = document.createElement("a");
    a.id = "soniq2fa-recover";
    a.href = "/service/extension/soniq2fa-recover";
    a.textContent = t("login.recover");
    a.style.cssText = "position:fixed;left:0;right:0;bottom:16px;text-align:center;font:13px -apple-system,'Segoe UI',Roboto," +
      "Helvetica,Arial,sans-serif;color:#2b73d2;text-decoration:none;z-index:10";
    document.body.appendChild(a);
  }

  // Carbonio's recovery refused: offer ours (accounts with 2FA have Carbonio's turned off).
  function offerRecovery(email) {
    var overlay = document.createElement("div");
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,.45);display:flex;align-items:center;" +
      "justify-content:center;z-index:2147483647;font:15px/1.5 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
    var box = document.createElement("div");
    box.style.cssText = "background:#fff;color:#333;border-radius:8px;padding:24px;width:min(92vw,400px);box-shadow:0 8px 32px rgba(0,0,0,.25)";
    var h = document.createElement("h2");
    h.textContent = t("login.recoverTitle");
    h.style.cssText = "font-size:18px;margin:0 0 8px";
    var p = document.createElement("p");
    p.textContent = t("login.recoverIntro");
    p.style.cssText = "margin:0 0 16px;color:#6b7280;font-size:14px";
    var go = document.createElement("a");
    go.textContent = t("login.recoverGo");
    go.href = "/service/extension/soniq2fa-recover?account=" + encodeURIComponent(email);
    go.style.cssText = "display:inline-block;background:#2b73d2;color:#fff;border-radius:6px;padding:8px 16px;text-decoration:none;margin-right:8px";
    var close = document.createElement("button");
    close.type = "button";
    close.textContent = t("login.cancel");
    close.style.cssText = "font:inherit;background:#fff;color:#2b73d2;border:1px solid #2b73d2;border-radius:6px;padding:8px 16px;cursor:pointer";
    close.onclick = function () { overlay.remove(); };
    [h, p, go, close].forEach(function (n) { box.appendChild(n); });
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    go.focus();
  }

  window.fetch = function (input, init) {
    var url = typeof input === "string" ? input : (input && input.url) || "";
    if (/\/service\/soap\/RecoverAccountRequest\b/.test(url) && init && typeof init.body === "string") {
      var rq = null;
      try { rq = JSON.parse(init.body).Body.RecoverAccountRequest; } catch (e) {}
      if (rq && rq.op === "getRecoveryAccount" && rq.email) {
        return realFetch(input, init).then(function (res) {
          if (!res.ok) domainUsesTwoFactor(rq.email).then(function (yes) { if (yes) offerRecovery(rq.email); });
          return res;
        });
      }
    }
    // webmail (/service/soap) and the admin console login (/service/admin/soap) send the same JSON
    var m = /\/service\/(?:admin\/)?soap\/(AuthRequest|ChangePasswordRequest)\b/.exec(url);
    if (!m || !init || typeof init.body !== "string") return realFetch(input, init);
    var json;
    try { json = JSON.parse(init.body); } catch (e) { return realFetch(input, init); }
    var req = json && json.Body && json.Body[m[1]];
    if (!req) return realFetch(input, init);
    var field = m[1] === "AuthRequest" ? req.password : req.oldPassword;
    var user = req.account && req.account._content;
    if (!field || typeof field._content !== "string" || !user) return send(input, init);
    return domainInfo(user).then(function (info) {
      if (info.twoFactor !== true) return send(input, init);
      var password = field._content;
      var sending = { user: user, password: password, info: info };
      function fault(res) {
        return res.clone().text().then(function (body) {
          return /TWO_FACTOR_AUTH_REQUIRED/.test(body) ? "need" : /TWO_FACTOR_AUTH_FAILED/.test(body) ? "badCode"
            : /AUTH_FAILED/.test(body) ? "failed" : "other";
        }, function () { return "other"; });
      }
      // Sends the password with the code; on a wrong code (newer server) asks again, telling the user why.
      function withCode(code) {
        field._content = password + code;
        return send(input, Object.assign({}, init, { body: JSON.stringify(json) })).then(function (res) {
          if (res.ok) { remember(user, code !== ""); return res; }
          if (!info.codeRequired) return res;
          return fault(res).then(function (f) {
            if (f === "badCode") return ask("need", t("err.invalid_code"));
            if (f === "need") return ask("need");
            return res;
          });
        });
      }
      function ask(mode, error) {
        return askCode(mode, sending, error).then(function (code) {
          if (code === null) return cancelled();
          if (code === "" && mode !== "ask") return cancelled();
          return withCode(code);
        });
      }
      if (remembered(user)) return ask("ask");
      return send(input, init).then(function (res) {
        if (res.ok) return res;
        return fault(res).then(function (f) {
          // newer server: the code only after the right password; a wrong password goes to the form as usual
          if (info.codeRequired) return f === "need" ? ask("need") : res;
          return f === "failed" ? ask("retry") : res;
        });
      });
    });
  };
})();
