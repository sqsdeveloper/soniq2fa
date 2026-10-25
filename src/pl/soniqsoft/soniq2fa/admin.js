// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
(function () {
  "use strict";
  var bundle = {}, fallback = {}, current = null;

  function t(key, vars) {
    var s = bundle[key] || fallback[key] || key;
    Object.keys(vars || {}).forEach(function (k) { s = s.split("{" + k + "}").join(vars[k]); });
    return s;
  }
  function $(id) { return document.getElementById(id); }
  function el(tag, text, cls) {
    var e = document.createElement(tag);
    if (text != null) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  }

  function message(text, ok) {
    var m = $("msg");
    m.hidden = !text;
    m.className = "msg " + (ok ? "ok" : "err");
    m.textContent = text || "";
  }

  function handle(r) {
    if (r.status === 401) { location.href = "/"; throw new Error("login"); }
    return r.json().catch(function () { throw new Error("server"); }).then(function (j) {
      if (!r.ok) throw new Error(j.error || "server");
      return j;
    });
  }
  function get(op, params) {
    return fetch("?" + new URLSearchParams(Object.assign({ op: op }, params || {})), { credentials: "same-origin" }).then(handle);
  }
  function post(op, params) {
    var body = new URLSearchParams(params);
    body.set("op", op);
    return fetch(location.pathname, { method: "POST", credentials: "same-origin", headers: { "X-Soniq2fa": "1" }, body: body }).then(handle);
  }
  function fail(e) { if (e.message !== "login") message(t("admin.err." + e.message)); }

  function select(values, value, onchange) {
    var s = el("select");
    values.forEach(function (v) {
      var o = el("option", t("admin.opt." + v));
      o.value = v;
      o.selected = v === value;
      s.appendChild(o);
    });
    s.onchange = function () { onchange(s.value, s); };
    return s;
  }

  function renderDomains(j) {
    var tb = $("domains");
    tb.textContent = "";
    j.domains.forEach(function (d) {
      var tr = el("tr");
      if (d.name === current) tr.className = "sel";
      tr.appendChild(el("td", d.name));
      var td = el("td");
      if (d.level === "other") td.appendChild(el("span", t("admin.opt.other"), "warn"));
      else td.appendChild(select(["off", "plain", "available", "required"], d.level, function (v, s) {
        var key = v === "off" ? "admin.confirm.off" : v === "required" ? "admin.confirm.requiredDomain" : null;
        if (key && !confirm(t(key, { domain: d.name }))) { s.value = d.level; return; }
        post("domain", { domain: d.name, level: v }).then(function (r) {
          renderDomains(r);
          message(t("admin.saved"), true);
          if (current === d.name) openDomain(d.name);
        }).catch(function (e) { s.value = d.level; fail(e); });
      }));
      tr.appendChild(td);
      // codes by SMS for the domain: the flag, and which gateway would send them
      var tds = el("td");
      if (d.level !== "off" && d.level !== "other") {
        var box = el("input");
        box.type = "checkbox";
        box.checked = d.sms;
        box.setAttribute("aria-label", t("admin.sms") + ": " + d.name);
        box.onchange = function () {
          post("domain-sms", { domain: d.name, on: box.checked }).then(function (r) {
            renderDomains(r);
            loadSms();
            message(t("admin.saved"), true);
          }).catch(function (e) { box.checked = !box.checked; fail(e); });
        };
        tds.appendChild(box);
        var gwName = d.smsGateway === "default" ? t("admin.sms.default") : d.smsGateway;
        if (d.sms) tds.appendChild(el("span", " " + (d.smsGateway ? t("admin.sms.via", { gateway: gwName }) : t("admin.sms.noGateway")),
          d.smsGateway ? "muted" : "warn"));
      }
      tr.appendChild(tds);
      var w = [];
      if (d.level !== "off" && d.level !== "other" && d.fallback) w.push(t("admin.warn.fallback"));
      if (d.level !== "off" && d.adminMech) w.push(t("admin.warn.adminMech"));
      tr.appendChild(el("td", w.join(" "), "err"));
      var open = el("button", t("admin.open"));
      open.onclick = function () { openDomain(d.name); };
      var tdo = el("td");
      if (d.level !== "off") tdo.appendChild(open);
      tr.appendChild(tdo);
      tb.appendChild(tr);
    });
  }

  // SMS gateways: read-only state from the file on the server, points and a test SMS on request
  function loadSms() {
    return get("sms").then(renderSms).catch(fail);
  }

  function renderSms(j) {
    $("sms-file").textContent = j.file;
    $("sms-state").textContent = t("admin.sms.state." + j.state);
    $("sms-state").className = j.state === "ok" ? "on" : j.state === "unreadable" ? "err" : "muted";
    var tb = $("gateways");
    tb.textContent = "";
    show("gateways-table", j.gateways.length > 0);
    j.gateways.forEach(function (g) {
      var tr = el("tr");
      var name = el("td", g.name === "default" ? t("admin.sms.default") : g.name);
      name.appendChild(el("span", (g.provider === "http" ? "HTTP" : "SMSAPI") + " · " + g.url, "sub"));
      tr.appendChild(name);
      tr.appendChild(el("td", t(g.configured ? "admin.sms.ready" : "admin.sms.incomplete"), g.configured ? "on" : "err"));
      tr.appendChild(el("td", g.from || t("admin.sms.accountDefault")));
      tr.appendChild(el("td", g.countries));
      tr.appendChild(el("td", g.sentThisHour + " / " + g.maxPerHour));
      // credentials are never shown: SMSAPI token as its length, an HTTP gateway as the names of its headers
      var cred = g.provider === "http" ? (g.headers ? t("admin.sms.headers", { names: g.headers }) : "–")
        : g.tokenLength ? t("admin.sms.tokenSet", { n: g.tokenLength }) : "–";
      tr.appendChild(el("td", cred, cred === "–" && g.provider !== "http" ? "err" : ""));
      tr.appendChild(el("td", g.domains.length ? g.domains.join(", ") : "–"));
      var act = el("td");
      var points = el("button", t("admin.sms.points"));
      var out = el("span", "", "sub out");
      points.onclick = function () {
        out.textContent = "…";
        post("sms-points", { gateway: g.name }).then(function (r) { out.textContent = t("admin.sms.pointsLeft", { points: r.points }); })
          .catch(function (e) { out.textContent = ""; fail(e); });
      };
      var phone = el("input");
      phone.type = "tel";
      phone.placeholder = "+48600111222";
      phone.setAttribute("aria-label", t("admin.sms.testPhone"));
      phone.style.width = "13ch";
      var test = el("button", t("admin.sms.test"));
      test.onclick = function () {
        out.textContent = "…";
        var body = new URLSearchParams({ op: "sms-test", gateway: g.name, phone: phone.value });
        fetch(location.pathname, { method: "POST", credentials: "same-origin", headers: { "X-Soniq2fa": "1" }, body: body }).then(function (r) {
          return r.json().then(function (j) {
            if (r.ok) { out.textContent = ""; message(t("admin.sms.sent", { phone: j.sent }), true); loadSms(); return; }
            out.textContent = "";
            message(t("admin.err." + (j.error || "server")) + (j.detail ? " — " + j.detail : ""));
          });
        }).catch(function () { out.textContent = ""; message(t("admin.err.server")); });
      };
      [g.balance ? points : null, el("span", " "), phone, el("span", " "), test, out].forEach(function (n) { if (n) act.appendChild(n); });
      tr.appendChild(act);
      tb.appendChild(tr);
    });
  }

  function show(id, on) { $(id).hidden = !on; }

  function openDomain(name) {
    current = name;
    get("accounts", { domain: name }).then(renderAccounts).then(function () {
      return get("domains").then(renderDomains);
    }).catch(fail);
  }

  // Account list: every column sorts (click the heading) and filters (text: contains, list: exact value).
  var data = null, sortKey = "account", sortDir = 1, filters = {};

  function stateLabel(a) {
    return a.enabled ? t("admin.state.on") : a.mustHave ? t("admin.state.pending") : a.offered ? t("admin.state.offered") : t("admin.state.off");
  }
  function yesNo(v) { return t(v ? "admin.opt.yes" : "admin.opt.no"); }
  // login codes by SMS and to the recovery address, besides the app
  function channels(a) {
    var c = [];
    if (a.enabled && a.sms) c.push("SMS");
    if (a.enabled && a.emailCodes) c.push(t("admin.channel.email"));
    return c.length ? c.join(", ") : "–";
  }
  var COLUMNS = [
    { key: "account", label: "admin.account", filter: "text", text: function (a) { return a.name + " " + (a.displayName || ""); }, sort: function (a) { return a.name; } },
    { key: "status", label: "admin.status", filter: "list", text: function (a) { return t("admin.status." + a.status); } },
    { key: "lastLogin", label: "admin.lastLogin", filter: "text", text: function (a) { return a.lastLogin || "–"; }, sort: function (a) { return a.lastLogin || ""; } },
    { key: "available", label: "admin.available", filter: "list", text: function (a) { return t("admin.opt." + a.available); } },
    { key: "required", label: "admin.required", filter: "list", text: function (a) { return t("admin.opt." + a.required); } },
    { key: "state", label: "admin.state", filter: "list", text: stateLabel },
    { key: "devices", label: "admin.devices", filter: "list", text: function (a) { return a.enabled ? String(a.devices) : "–"; }, sort: function (a) { return a.enabled ? a.devices : -1; } },
    { key: "backup", label: "admin.backup", filter: "list", text: function (a) { return a.enabled ? String(a.backupLeft) : "–"; }, sort: function (a) { return a.enabled ? a.backupLeft : -1; } },
    { key: "channels", label: "admin.channels", filter: "list", text: channels },
    { key: "recovery", label: "admin.recovery", filter: "list", text: function (a) { return yesNo(a.recovery); } }
  ];

  function buildHead() {
    var head = $("accounts-head");
    head.textContent = "";
    var labels = el("tr"), row = el("tr", null, "filters");
    COLUMNS.forEach(function (c) {
      var th = el("th", t(c.label) + (sortKey === c.key ? (sortDir > 0 ? " ▲" : " ▼") : ""), "sort");
      th.setAttribute("aria-sort", sortKey === c.key ? (sortDir > 0 ? "ascending" : "descending") : "none");
      th.onclick = function () {
        sortDir = sortKey === c.key ? -sortDir : 1;
        sortKey = c.key;
        buildHead();
        drawRows();
      };
      labels.appendChild(th);
      var cell = el("th"), input;
      if (c.filter === "text") {
        input = el("input");
        input.type = "search";
        input.value = filters[c.key] || "";
        input.oninput = function () { filters[c.key] = input.value; drawRows(); };
      } else {
        input = el("select");
        var all = el("option", t("admin.filter.all"));
        all.value = "";
        input.appendChild(all);
        var values = {};
        data.accounts.forEach(function (a) { values[c.text(a)] = true; });
        Object.keys(values).sort().forEach(function (v) {
          var o = el("option", v);
          o.value = v;
          o.selected = filters[c.key] === v;
          input.appendChild(o);
        });
        input.onchange = function () { filters[c.key] = input.value; drawRows(); };
      }
      input.setAttribute("aria-label", t("admin.filter") + ": " + t(c.label));
      cell.appendChild(input);
      row.appendChild(cell);
    });
    labels.appendChild(el("th"));
    row.appendChild(el("th"));
    head.appendChild(labels);
    head.appendChild(row);
  }

  function visible() {
    var list = data.accounts.filter(function (a) {
      return COLUMNS.every(function (c) {
        var f = filters[c.key];
        if (!f) return true;
        var v = c.text(a);
        return c.filter === "text" ? v.toLowerCase().indexOf(f.toLowerCase()) >= 0 : v === f;
      });
    });
    var col = COLUMNS.filter(function (c) { return c.key === sortKey; })[0];
    var key = col.sort || col.text;
    return list.sort(function (x, y) {
      var a = key(x), b = key(y);
      return (a < b ? -1 : a > b ? 1 : x.name < y.name ? -1 : 1) * sortDir;
    });
  }

  function renderAccounts(j) {
    var fresh = !data || data.domain !== j.domain;
    if (fresh) filters = {};
    data = j;
    $("accounts-box").hidden = false;
    $("domain-name").textContent = j.domain;
    buildHead();
    drawRows();
  }

  function drawRows() {
    var j = data, tb = $("accounts"), list = visible();
    tb.textContent = "";
    $("accounts-count").textContent = t("admin.shown", { shown: list.length, total: j.accounts.length });
    list.forEach(function (a) {
      var tr = el("tr");
      if (a.status === "closed") tr.className = "closed";
      var who = el("td");
      var link = el("a", a.name, "account");
      link.href = "/carbonioAdmin/manage/domains/" + encodeURIComponent(j.domainId) + "/accounts";
      link.target = "_blank";
      link.rel = "noopener";
      link.title = t("admin.openInConsole");
      who.appendChild(link);
      if (a.displayName) who.appendChild(el("span", a.displayName, "sub"));
      tr.appendChild(who);
      tr.appendChild(el("td", t("admin.status." + a.status), a.status === "active" ? "" : a.status === "closed" ? "muted" : "err"));
      tr.appendChild(el("td", a.lastLogin || "–", "muted"));
      ["available", "required"].forEach(function (attr) {
        var td = el("td");
        td.appendChild(select(["inherit", "yes", "no"], a[attr], function (v, s) {
          if (attr === "required" && v === "yes" && !confirm(t("admin.confirm.required", { account: a.name }))) { s.value = a[attr]; return; }
          post("account", { account: a.name, attr: attr, value: v }).then(function (r) {
            renderAccounts(r);
            message(t("admin.saved"), true);
          }).catch(function (e) { s.value = a[attr]; fail(e); });
        }));
        tr.appendChild(td);
      });
      tr.appendChild(el("td", stateLabel(a), a.enabled ? "on" : a.mustHave ? "warn" : "muted"));
      tr.appendChild(el("td", a.enabled ? String(a.devices) : "–"));
      tr.appendChild(el("td", a.enabled ? String(a.backupLeft) : "–", a.enabled && a.backupLeft < 3 ? "warn" : ""));
      tr.appendChild(el("td", channels(a)));
      var rec = el("td");
      var box = el("input");
      box.type = "checkbox";
      box.checked = a.recovery;
      box.setAttribute("aria-label", t("admin.recovery") + ": " + a.name);
      box.onchange = function () {
        if (box.checked && a.enabled && !confirm(t("admin.confirm.recovery", { account: a.name }))) { box.checked = false; return; }
        post("recovery", { account: a.name, on: box.checked }).then(function (r) {
          renderAccounts(r);
          message(box.checked && a.enabled ? t("admin.warn.recoveryOn", { account: a.name }) : t("admin.saved"), !(box.checked && a.enabled));
        }).catch(function (e) { box.checked = !box.checked; fail(e); });
      };
      rec.appendChild(box);
      if (a.recovery && a.enabled) rec.appendChild(el("span", " " + t("admin.warn.recovery"), "err"));
      tr.appendChild(rec);
      var act = el("td");
      if (a.enabled) {
        var reset = el("button", t("admin.reset"), "danger");
        reset.onclick = function () {
          if (!confirm(t("admin.confirm.reset", { account: a.name }))) return;
          post("reset", { account: a.name }).then(function (r) {
            renderAccounts(r);
            message(t("admin.resetDone", { account: a.name }), true);
          }).catch(fail);
        };
        act.appendChild(reset);
      }
      tr.appendChild(act);
      tb.appendChild(tr);
    });
  }

  get("i18n").then(function (i) {
    bundle = i.messages || {};
    fallback = i.fallback || {};
    document.documentElement.lang = i.lang || "en";
    document.querySelectorAll("[data-i18n]").forEach(function (e) { e.textContent = t(e.getAttribute("data-i18n")); });
    return get("domains");
  }).then(renderDomains).then(loadSms).catch(fail);
})();
