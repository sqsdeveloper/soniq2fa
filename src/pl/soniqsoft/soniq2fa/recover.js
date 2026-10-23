// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
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
    return fetch("", { method: "POST", credentials: "same-origin", headers: { "X-Soniq2fa": "1" }, body: body })
      .then(function (r) {
        return r.json().catch(function () { return { error: "server" }; }).then(function (j) {
          if (!r.ok) { var e = new Error(j.error || "server"); e.detail = j.detail; throw e; }
          return j;
        });
      });
  }

  function show(step) {
    ["step1", "step2", "done"].forEach(function (id) { $(id).hidden = id !== step; });
  }

  function start() {
    return post("start", { account: $("account").value.trim() }).then(function () {
      show("step2");
      message(t("recover.sent"), true);
      $("mail-code").focus();
    });
  }

  $("start-form").onsubmit = function (e) {
    e.preventDefault();
    start().catch(function () { message(t("err.server")); });
  };

  $("again").onclick = function () {
    start().catch(function () { message(t("err.server")); });
  };

  $("finish-form").onsubmit = function (e) {
    e.preventDefault();
    if ($("password").value !== $("password2").value) {
      message(t("recover.err.mismatch"));
      $("password2").focus();
      return;
    }
    post("finish", {
      account: $("account").value.trim(),
      mailCode: $("mail-code").value,
      code: $("code").value.replace(/\s+/g, ""),
      password: $("password").value
    }).then(function () {
      $("password").value = $("password2").value = "";
      show("done");
      message("");
      try { localStorage.setItem("soniq2fa:" + $("account").value.trim().toLowerCase(), "1"); } catch (x) {}
    }).catch(function (err) {
      var key = "recover.err." + err.message;
      var text = bundle[key] || fallback[key] ? t(key) : bundle["err." + err.message] || fallback["err." + err.message] ? t("err." + err.message) : t("err.server");
      message(err.detail ? text + " (" + err.detail + ")" : text);
    });
  };

  fetch("?op=i18n", { credentials: "same-origin" }).then(function (r) { return r.json(); }).then(function (i) {
    bundle = i.messages || {};
    fallback = i.fallback || {};
    document.documentElement.lang = i.lang || "en";
    document.querySelectorAll("[data-i18n]").forEach(function (e) { e.textContent = t(e.getAttribute("data-i18n")); });
    var q = new URLSearchParams(location.search).get("account");
    if (q) $("account").value = q;
  });
})();
