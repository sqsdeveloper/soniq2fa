// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Setting up 2FA without a session, for an account that must use it once its grace period is over (the login page
// links here with ?op=enroll&account=...): address and password, QR code, first code, backup codes.
(function () {
  "use strict";
  var bundle = {}, fallback = {};

  function t(key) { return bundle[key] || fallback[key] || key; }
  function $(id) { return document.getElementById(id); }

  function message(text, ok) {
    var m = $("msg");
    m.hidden = !text;
    m.className = "msg " + (ok ? "ok" : "err");
    m.setAttribute("role", ok ? "status" : "alert");
    m.textContent = text || "";
  }

  function post(op, params) {
    var body = new URLSearchParams(params);
    body.set("op", op);
    return fetch(location.pathname, { method: "POST", credentials: "same-origin", headers: { "X-Soniq2fa": "1" }, body: body })
      .then(function (r) {
        return r.json().catch(function () { return { error: "server" }; }).then(function (j) {
          if (!r.ok) throw new Error(j.error || "server");
          return j;
        });
      });
  }

  function fail(e) {
    var key = "enroll.err." + e.message;
    message(bundle[key] || fallback[key] ? t(key) : bundle["err." + e.message] || fallback["err." + e.message] ? t("err." + e.message) : t("err.server"));
  }

  function show(step) {
    ["step1", "step2", "done"].forEach(function (id) { $(id).hidden = id !== step; });
  }

  function login() { return { account: $("account").value.trim(), password: $("password").value }; }

  $("start-form").onsubmit = function (e) {
    e.preventDefault();
    post("enroll-start", login()).then(function (r) {
      var qr = qrcode(0, "M");
      qr.addData(r.uri);
      qr.make();
      $("qr").innerHTML = qr.createSvgTag({ cellSize: 5, margin: 2 });
      $("secret").textContent = r.secret.replace(/(.{4})/g, "$1 ").trim();
      message("");
      show("step2");
      $("code").focus();
    }).catch(fail);
  };

  $("confirm-form").onsubmit = function (e) {
    e.preventDefault();
    var p = login();
    p.code = $("code").value.replace(/\s+/g, "");
    post("enroll-confirm", p).then(function (r) {
      $("password").value = "";
      $("qr").textContent = "";
      $("secret").textContent = "";
      var ol = $("codes");
      ol.textContent = "";
      r.codes.forEach(function (c) { var li = document.createElement("li"); li.textContent = c; ol.appendChild(li); });
      message("");
      show("done");
      try { localStorage.setItem("soniq2fa:" + p.account.toLowerCase(), "1"); } catch (x) {}
    }).catch(function (err) { fail(err); $("code").select(); });
  };

  fetch("?op=i18n", { credentials: "same-origin" }).then(function (r) { return r.json(); }).then(function (i) {
    bundle = i.messages || {};
    fallback = i.fallback || {};
    document.documentElement.lang = i.lang || "en";
    document.querySelectorAll("[data-i18n]").forEach(function (e) { e.textContent = t(e.getAttribute("data-i18n")); });
    var q = new URLSearchParams(location.search).get("account");
    if (q) { $("account").value = q; $("password").focus(); }
  });
})();
