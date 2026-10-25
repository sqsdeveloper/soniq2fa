// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var account = "";
  var lastCodes = [];
  var bundle = {}, fallback = {};

  // Shown inside webmail Settings (install/settings): the webmail around it already leads back to mail.
  if (window !== window.top) document.querySelector("header").hidden = true;

  // Text for a key in the user's language, English when the translation lacks it; {name} placeholders filled from vars.
  function t(key, vars) {
    var s = bundle[key] || fallback[key] || key;
    return s.replace(/\{(\w+)\}/g, function (m, k) { return vars && k in vars ? vars[k] : m; });
  }

  function translate() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-i18n]"), function (el) { el.textContent = t(el.dataset.i18n); });
    Array.prototype.forEach.call(document.querySelectorAll("[data-i18n-placeholder]"), function (el) {
      el.placeholder = t(el.dataset.i18nPlaceholder);
      el.setAttribute("aria-label", t(el.dataset.i18nPlaceholder));
    });
    Array.prototype.forEach.call(document.querySelectorAll("[data-i18n-label]"), function (el) { el.setAttribute("aria-label", t(el.dataset.i18nLabel)); });
  }

  function show(id, on) { $(id).hidden = !on; }

  // Shown inside the section where the action happened (below its heading), so it is on screen next to the button.
  function message(text, ok, sectionId, input) {
    Array.prototype.forEach.call(document.querySelectorAll(".msg"), function (m) { m.remove(); });
    if (!text) return;
    var d = document.createElement("div");
    d.className = "msg " + (ok ? "ok" : "err");
    d.setAttribute("role", ok ? "status" : "alert");
    d.textContent = text;
    var host = sectionId ? $(sectionId) : $("msg");
    if (sectionId && host.firstElementChild) host.insertBefore(d, host.firstElementChild.nextSibling);
    else host.appendChild(d);
    d.scrollIntoView({ block: "nearest", behavior: "smooth" });
    if (input && !ok) { input.focus(); input.select(); }
  }

  // Server error codes map to err.<code>; anything else (network failure, a proxy error page) is a generic error.
  function fail(sectionId, input) {
    return function (e) {
      if (e.message === "login") return;
      var key = "err." + e.message;
      message(bundle[key] || fallback[key] ? t(key) : t("err.server"), false, sectionId, input);
    };
  }

  function code(id) { return $(id).value.replace(/\s+/g, ""); }

  function copy(text, button) {
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText(text).then(function () { button.textContent = t("copied"); }, function () {});
  }

  function call(op, params) {
    var body = new URLSearchParams(params || {});
    body.set("op", op);
    return fetch(location.pathname, { method: "POST", credentials: "same-origin", headers: { "X-Soniq2fa": "1" }, body: body })
      .then(function (r) {
        if (r.status === 401) { top.location.href = "/"; throw new Error("login"); }
        return r.json().catch(function () { throw new Error("server"); }).then(function (j) {
          if (!r.ok) throw new Error(j.error || "server");
          return j;
        });
      });
  }

  // Tells the login page script (same origin) to ask this browser's user for the code before the first attempt.
  function remember(user, on) {
    try {
      if (on) localStorage.setItem("soniq2fa:" + user.toLowerCase(), "1");
      else localStorage.removeItem("soniq2fa:" + user.toLowerCase());
    } catch (e) {}
  }

  function getState() {
    return fetch("?op=state", { credentials: "same-origin" }).then(function (r) {
      if (r.status === 401) { top.location.href = "/"; throw new Error("login"); }
      return r.json();
    });
  }

  function render(s) {
    account = s.account;
    show("unavailable", !s.available && !s.enabled);
    $("unavailable-reason").textContent = s.reason ? t("unavailable." + s.reason) : "";
    show("off", s.available && !s.enabled);
    show("on", s.enabled);
    show("devices", s.enabled);
    show("disable-box", s.enabled && !s.required);
    show("rekey-box", s.enabled && s.required);
    show("recovery-warn", s.enabled && s.recovery);
    show("address-box", s.enabled);
    show("channels-box", s.enabled);
    show("sms-unavailable", !s.smsAvailable);
    show("sms-box", !!s.smsAvailable);
    $("phone-current").textContent = s.phone || t("channels.smsNone");
    show("phone-remove", !!s.phone);
    $("email-state").textContent = t(s.emailCodes ? "channels.yes" : "channels.no");
    show("email-needs-address", !s.emailCodes && !s.recoveryAddress);
    show("email-on", !s.emailCodes && !!s.recoveryAddress);
    show("email-off", !!s.emailCodes);
    $("address-current").textContent = s.recoveryAddress || t("address.none");
    remember(s.account, s.enabled);
    show("backup", s.enabled);
    $("backup-left").textContent = String(s.backupLeft || 0);
    if (s.codes) showCodes(s.codes);
    var list = $("device-list");
    list.textContent = "";
    (s.devices || []).forEach(function (label) {
      var li = document.createElement("li");
      var name = document.createElement("span");
      name.textContent = label;
      var del = document.createElement("button");
      del.className = "danger";
      del.textContent = t("devices.remove");
      del.onclick = function () {
        if (!confirm(t("confirm.remove", { label: label }))) return;
        call("revoke", { label: label }).then(function (st) { render(st); message(t("msg.removed", { label: label }), true, "devices"); })
          .catch(fail("devices"));
      };
      li.appendChild(name);
      li.appendChild(del);
      list.appendChild(li);
    });
    show("no-devices", !(s.devices || []).length);
  }

  function showCodes(codes) {
    lastCodes = codes;
    var ol = $("codes");
    ol.textContent = "";
    codes.forEach(function (c) { var li = document.createElement("li"); li.textContent = c; ol.appendChild(li); });
    show("codes-box", true);
  }

  function codesText() {
    return t("backup.file") + "\n" + account + "\n\n" + lastCodes.join("\n") + "\n";
  }

  $("start").onclick = function () {
    message("");
    call("start").then(function (r) {
      var qr = qrcode(0, "M");
      qr.addData(r.uri);
      qr.make();
      $("qr").innerHTML = qr.createSvgTag({ cellSize: 5, margin: 2 });
      $("secret").textContent = r.secret.replace(/(.{4})/g, "$1 ").trim();
      show("off", false);
      show("rekey-box", false);
      show("enroll", true);
      $("confirm-code").focus();
    }).catch(fail("off"));
  };

  $("cancel").onclick = function () {
    show("enroll", false);
    $("qr").textContent = "";
    getState().then(render).catch(fail(null));
  };

  $("confirm").onclick = function () {
    call("confirm", { password: $("confirm-password").value, code: code("confirm-code") }).then(function (st) {
      $("confirm-password").value = "";
      show("enroll", false);
      $("qr").textContent = "";
      $("secret").textContent = "";
      render(st);
      message(t("msg.enabled"), true, "on");
    }).catch(function (e) {
      fail("enroll", e.message === "invalid_password" ? $("confirm-password") : $("confirm-code"))(e);
    });
  };

  $("rekey").onclick = $("start").onclick;

  $("address-send").onclick = function () {
    call("address", { address: $("address").value.trim(), password: $("address-password").value }).then(function (r) {
      $("address-password").value = "";
      show("address-verify", true);
      message(t("address.sent", { address: r.pending }), true, "address-box");
      $("address-code").focus();
    }).catch(function (e) { fail("address-box", e.message === "invalid_password" ? $("address-password") : $("address"))(e); });
  };

  $("address-confirm").onclick = function () {
    call("address-confirm", { code: code("address-code") }).then(function (st) {
      $("address").value = $("address-code").value = "";
      show("address-verify", false);
      render(st);
      message(t("address.saved"), true, "address-box");
    }).catch(fail("address-box", $("address-code")));
  };

  // the same forms the server accepts (Channels.normalizePhone): +48600111222, 0048600111222, 600111222
  function phoneValid(v) {
    var s = v.trim().replace(/([0-9])[ -](?=[0-9])/g, "$1");
    if (/^00[1-9][0-9]{7,14}$/.test(s)) s = "+" + s.slice(2);
    else if (/^[0-9]{9}$/.test(s)) s = "+48" + s;
    return /^\+[1-9][0-9]{7,14}$/.test(s) && (s.indexOf("+48") !== 0 || /^\+48[4-8][0-9]{8}$/.test(s));
  }
  function checkPhone() {
    var v = $("phone").value, ok = phoneValid(v);
    $("phone-send").disabled = !ok;
    $("phone-format").className = v.trim() && !ok ? "msg err" : "muted";
  }
  $("phone").addEventListener("input", checkPhone);
  checkPhone();

  $("phone-send").onclick = function () {
    if (!phoneValid($("phone").value)) return;
    call("phone", { phone: $("phone").value.trim(), password: $("channels-password").value }).then(function (r) {
      $("channels-password").value = "";
      show("phone-verify", true);
      message(t("channels.smsSent", { phone: r.pending }), true, "channels-box");
      $("phone-code").focus();
    }).catch(function (e) { fail("channels-box", e.message === "invalid_password" ? $("channels-password") : $("phone"))(e); });
  };

  $("phone-confirm").onclick = function () {
    call("phone-confirm", { code: code("phone-code") }).then(function (st) {
      $("phone").value = $("phone-code").value = "";
      checkPhone();
      show("phone-verify", false);
      render(st);
      message(t("channels.smsSaved"), true, "channels-box");
    }).catch(fail("channels-box", $("phone-code")));
  };

  $("phone-remove").onclick = function () {
    if (!confirm(t("confirm.phoneRemove"))) return;
    call("phone-remove").then(function (st) { render(st); message(t("channels.smsRemoved"), true, "channels-box"); })
      .catch(fail("channels-box"));
  };

  function emailCodes(on) {
    call("email-codes", { on: on ? "1" : "0", password: on ? $("channels-password").value : "" }).then(function (st) {
      $("channels-password").value = "";
      render(st);
      message(t(on ? "channels.emailOnMsg" : "channels.emailOffMsg"), true, "channels-box");
    }).catch(fail("channels-box", $("channels-password")));
  }
  $("email-on").onclick = function () { emailCodes(true); };
  $("email-off").onclick = function () { emailCodes(false); };

  $("create").onclick = function () {
    call("create", { label: $("label").value }).then(function (r) {
      $("new-label").textContent = r.label;
      $("new-pw").textContent = r.password;
      $("cfg-user").textContent = account;
      Array.prototype.forEach.call(document.querySelectorAll(".cfg-host"), function (el) { el.textContent = location.hostname; });
      $("label").value = "";
      return getState().then(function (st) {
        render(st);
        show("new-password", true);
        message(t("msg.created", { label: r.label }), true, "devices");
      });
    }).catch(fail("devices", $("label")));
  };

  $("copy").onclick = function () { copy($("new-pw").textContent, $("copy")); };

  $("codes-copy").onclick = function () { copy(codesText(), $("codes-copy")); };

  $("codes-download").onclick = function () {
    var a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([codesText()], { type: "text/plain" }));
    a.download = "backup-codes-" + account + ".txt";
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  };

  $("codes-new").onclick = function () {
    if (!confirm(t("confirm.newCodes"))) return;
    call("codes").then(function (st) {
      render(st);
      message(t("msg.newCodes"), true, "backup");
    }).catch(fail("backup"));
  };

  $("disable").onclick = function () {
    if (!confirm(t("confirm.disable"))) return;
    call("disable").then(function (st) {
      show("new-password", false);
      show("codes-box", false);
      render(st);
      message(t("msg.disabled"), true, "off");
    }).catch(fail("disable-box"));
  };

  fetch("?op=i18n", { credentials: "same-origin" })
    .then(function (r) { return r.json(); })
    .then(function (i) {
      bundle = i.messages || {};
      fallback = i.fallback || {};
      document.documentElement.lang = i.lang || "en";
      translate();
      return getState();
    })
    .then(function (s) { render(s); document.body.classList.remove("loading"); })
    .catch(function (e) {
      document.body.classList.remove("loading");
      if (e.message !== "login") message(t("err.load"));
    });
})();
