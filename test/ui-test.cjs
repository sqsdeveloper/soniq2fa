// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Browser tests of the web parts (self-service page, webmail Settings module, login page script, administration page)
// in WebKit, against a local server that serves the real files and answers the extension API with fictitious data.
// No Carbonio needed; the server side is covered by tests on a real installation.
//   npm i playwright && npx playwright install webkit
//   node test/ui-test.cjs            run the tests
//   node test/ui-test.cjs --shots    also write the documentation screenshots to docs/ (en and pl)
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const { webkit } = require("playwright");

const ROOT = path.join(__dirname, "..");
const SRC = path.join(ROOT, "src/pl/soniqsoft/soniq2fa");
const SHOTS = process.argv.includes("--shots");
const USER = "anna.kowalska@example.com";
const SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const CODES = ["k7m2q-x9p4r", "h3n8t-w2c6v", "b5j9d-z4k7m", "q2w8e-r5t3y", "u6i9o-p2a4s",
  "d7f3g-h8j2k", "l4z6x-c9v3b", "n2m7q-w5e8r", "t3y6u-i9o2p", "a5s8d-f2g4h"];
let lang = "en", st, admin, posts, bad = 0, total = 0;

function check(ok, name) {
  total++;
  if (!ok) bad++;
  console.log(`${ok ? "OK  " : "FAIL"} [${lang}] ${name}`);
}

function bundle(l) { return fs.readFileSync(path.join(SRC, "i18n", l + ".json"), "utf8"); }

function reset(over) {
  st = Object.assign({ account: USER, available: true, reason: null, enabled: false, required: false, recovery: false,
    devices: [], backupLeft: 0, smsAvailable: true, phone: "", emailCodes: false }, over);
  admin = {
    domains: [
      { name: "example.com", level: "plain", fallback: false, adminMech: false, sms: true, smsGateway: "default" },
      { name: "example.org", level: "required", fallback: false, adminMech: false, sms: false, smsGateway: "example.org" },
      { name: "example.net", level: "off", fallback: true, adminMech: false, sms: false, smsGateway: "" }],
    sms: { file: "/opt/zextras/lib/ext/soniq2fa/soniq2fa.properties", state: "ok", gateways: [
      { name: "default", configured: true, provider: "smsapi", from: "Example", countries: "+48", maxPerHour: "200",
        url: "https://api.smsapi.pl/sms.do", tokenLength: 40, headers: "", balance: true, sentThisHour: 3, domains: ["example.com"] },
      { name: "example.org", configured: true, provider: "smsapi", from: "ExampleOrg", countries: "+48,+420", maxPerHour: "50",
        url: "https://api.smsapi.pl/sms.do", tokenLength: 40, headers: "", balance: true, sentThisHour: 0, domains: [] },
      { name: "example.net", configured: true, provider: "http", from: "+15005550006", countries: "+48", maxPerHour: "100",
        url: "https://api.example.com/2010-04-01/Accounts/AC1/Messages.json", tokenLength: 0, headers: "Authorization, Content-Type",
        balance: false, sentThisHour: 0, domains: [] }] },
    accounts: [
      { name: "anna.kowalska@example.com", displayName: "Anna Kowalska", status: "active", lastLogin: "2026-10-10", available: "yes", required: "inherit", offered: true, mustHave: false, enabled: true, devices: 3, backupLeft: 8, recovery: false },
      { name: "jan.nowak@example.com", displayName: "Jan Nowak", status: "active", lastLogin: "2026-10-08", available: "yes", required: "yes", offered: true, mustHave: true, enabled: false, devices: 0, backupLeft: 0, recovery: false },
      { name: "piotr.wisniewski@example.com", displayName: "Piotr Wiśniewski", status: "lockout", lastLogin: "2026-09-30", available: "inherit", required: "inherit", offered: false, mustHave: false, enabled: false, devices: 0, backupLeft: 0, recovery: true },
      { name: "biuro@example.com", displayName: "Biuro", status: "active", lastLogin: "2026-10-09", available: "yes", required: "inherit", offered: true, mustHave: false, enabled: true, devices: 1, backupLeft: 2, recovery: false }]
  };
  posts = [];
}

function send(res, status, body, type) {
  res.writeHead(status, { "Content-Type": type || "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}

function i18n(res) { send(res, 200, `{"lang":"${lang}","messages":${bundle(lang)},"fallback":${bundle("en")}}`); }

function userApi(req, res, q, form) {
  if (req.method === "GET") {
    const op = q.get("op");
    if (op === "app.js" || op === "qrcode.js") return send(res, 200, fs.readFileSync(path.join(SRC, op)), "text/javascript");
    if (op === "i18n") return i18n(res);
    if (op === "state") return send(res, 200, st);
    if (op === "domain") return send(res, 200, { twoFactor: q.get("name") === "example.com", sms: q.get("name") === "example.com",
      codeRequired: q.get("name") === "example.com" });
    return send(res, 200, fs.readFileSync(path.join(SRC, "page.html")), "text/html; charset=utf-8");
  }
  posts.push(Object.fromEntries(form));
  if (!req.headers["x-soniq2fa"]) return send(res, 403, { error: "rejected" });
  switch (form.get("op")) {
    case "start":
      return send(res, 200, { secret: SECRET, uri: `otpauth://totp/example.com:${encodeURIComponent(USER)}?secret=${SECRET}&issuer=example.com` });
    case "confirm":
      if (form.get("code") !== "123456") return send(res, 400, { error: "invalid_code" });
      Object.assign(st, { enabled: true, backupLeft: 10, recovery: false });
      return send(res, 200, Object.assign({}, st, { codes: CODES }));
    case "create":
      st.devices.push(form.get("label"));
      return send(res, 200, { password: "wq7k-p3mz-8tdx-r2vn", label: form.get("label") });
    case "revoke":
      st.devices = st.devices.filter((d) => d !== form.get("label"));
      return send(res, 200, st);
    case "codes":
      return send(res, 200, Object.assign({}, st, { backupLeft: 10, codes: CODES }));
    case "address":
      if (!/@.+\./.test(form.get("address") || "")) return send(res, 400, { error: "bad_address" });
      return send(res, 200, { pending: "a***@private.example" });
    case "address-confirm":
      if (form.get("code") !== "12345678") return send(res, 400, { error: "invalid_mail_code" });
      st.recoveryAddress = "a***@private.example";
      return send(res, 200, st);
    case "phone":
      if (!/^(\+48|0048)?[4-8][0-9 ]{8,}$/.test(form.get("phone") || "")) return send(res, 400, { error: "bad_phone" });
      if (form.get("password") !== "Haslo-2026") return send(res, 400, { error: "invalid_password" });
      return send(res, 200, { pending: "+48 *** *** 222" });
    case "phone-confirm":
      if (form.get("code") !== "654321") return send(res, 400, { error: "invalid_sms_code" });
      st.phone = "+48 *** *** 222";
      return send(res, 200, st);
    case "phone-remove":
      st.phone = "";
      return send(res, 200, st);
    case "email-codes":
      if (form.get("on") === "1" && !st.recoveryAddress) return send(res, 400, { error: "address_first" });
      if (form.get("on") === "1" && form.get("password") !== "Haslo-2026") return send(res, 400, { error: "invalid_password" });
      st.emailCodes = form.get("on") === "1";
      return send(res, 200, st);
    case "disable":
      if (st.required) return send(res, 400, { error: "required" });
      Object.assign(st, { enabled: false, devices: [], backupLeft: 0 });
      return send(res, 200, st);
  }
  send(res, 400, { error: "rejected" });
}

let recovered = null;
function recoverApi(req, res, q, form) {
  if (req.method === "GET") {
    const op = q.get("op");
    if (op === "recover.js") return send(res, 200, fs.readFileSync(path.join(SRC, op)), "text/javascript");
    if (op === "i18n") return i18n(res);
    return send(res, 200, fs.readFileSync(path.join(SRC, "recover.html")), "text/html; charset=utf-8");
  }
  posts.push(Object.fromEntries(form));
  if (form.get("op") === "start" || form.get("op") === "send") return send(res, 200, { ok: true });
  if (form.get("mailCode") !== "87654321") return send(res, 400, { error: "invalid_mail_code" });
  if (form.get("code") !== "123456") return send(res, 400, { error: "invalid_code" });
  if ((form.get("password") || "").length < 8) return send(res, 400, { error: "password_policy", detail: "too short" });
  recovered = form.get("password");
  send(res, 200, { ok: true });
}

function adminApi(req, res, q, form) {
  if (req.method === "GET") {
    const op = q.get("op");
    if (op === "admin.js") return send(res, 200, fs.readFileSync(path.join(SRC, op)), "text/javascript");
    if (op === "i18n") return i18n(res);
    if (op === "domains") return send(res, 200, { domains: admin.domains });
    if (op === "sms") return send(res, 200, admin.sms);
    if (op === "accounts") return send(res, 200, { domain: q.get("domain"), domainId: "0f3c9a52-1d1e-4b7a-9c55-6a1e2f9b7d10", level: "plain", accounts: admin.accounts });
    return send(res, 200, fs.readFileSync(path.join(SRC, "admin.html")), "text/html; charset=utf-8");
  }
  posts.push(Object.fromEntries(form));
  const a = admin.accounts.find((x) => x.name === form.get("account"));
  switch (form.get("op")) {
    case "domain":
      admin.domains.find((d) => d.name === form.get("domain")).level = form.get("level");
      return send(res, 200, { domains: admin.domains });
    case "domain-sms":
      admin.domains.find((d) => d.name === form.get("domain")).sms = form.get("on") === "true";
      return send(res, 200, { domains: admin.domains });
    case "sms-points": return send(res, 200, { points: "86.29" });
    case "sms-test":
      if (!/^\+48[4-8][0-9]{8}$/.test(form.get("phone") || "")) return send(res, 400, { error: "bad_phone" });
      return send(res, 200, { sent: "+48 *** *** 222" });
    case "account": a[form.get("attr")] = form.get("value"); break;
    case "recovery": a.recovery = form.get("on") === "true"; break;
    case "reset": Object.assign(a, { enabled: false, devices: 0, backupLeft: 0 }); break;
  }
  send(res, 200, { domain: "example.com", domainId: "0f3c9a52-1d1e-4b7a-9c55-6a1e2f9b7d10", level: "plain", accounts: admin.accounts });
}

// Stand-ins for the hosts of the two scripts that run inside Carbonio pages: the webmail shell (Settings module) and the
// login form (it sends AuthRequest through fetch, as carbonio-login-ui does).
const SETTINGS_HOST = `<!doctype html><meta charset="utf-8"><body style="margin:0;font:15px sans-serif;background:#eef1f5">
<div style="height:48px;background:#2b73d2"></div><div style="padding:24px;color:#556">Inbox</div>
<script>
  window.added = [];
  window.__ZAPP_SHARED_LIBRARIES__ = { react: { createElement: function () { return null; }, useEffect: function (f) { f(); } },
    "@zextras/carbonio-shell-ui": { "soniq2fa-ui": { addSettingsView: function (v) { window.added.push(v.label); } } } };
  window.__ZAPP_HMR_EXPORT__ = { "soniq2fa-ui": function (App) { App(); } };
</script><script src="/install/settings/app.js"></script>`;
const ADMIN_CONSOLE_HOST = `<!doctype html><meta charset="utf-8"><script defer src="/install/admin-link.js"></script>
<body style="margin:0;font:15px sans-serif"><div style="height:48px;background:#2b73d2"></div><p style="padding:24px">Admin console</p>`;
// the admin console login page: same script with data-admin, AuthRequest to /service/admin/soap
const ADMIN_LOGIN_HOST = `<!doctype html><meta charset="utf-8"><script src="/install/login.js" data-admin></script>
<body style="font:15px sans-serif;padding:40px"><form id="f"><input id="u"> <input id="p" type="password"> <button>Sign in</button></form>
<p id="out"></p><script>
  document.getElementById("f").onsubmit = function (e) {
    e.preventDefault();
    var body = { Body: { AuthRequest: { _jsns: "urn:zimbraAdmin", account: { by: "name", _content: document.getElementById("u").value },
      password: { _content: document.getElementById("p").value } } } };
    fetch("/service/admin/soap/AuthRequest", { method: "POST", body: JSON.stringify(body) }).then(function (r) {
      document.getElementById("out").textContent = r.ok ? "signed in" : "refused";
    });
  };
</script>`;
const LOGIN_HOST = `<!doctype html><meta charset="utf-8"><script src="/install/login.js"></script>
<body style="font:15px sans-serif;padding:40px"><form id="f"><input id="u"> <input id="p" type="password"> <button>Sign in</button></form>
<p id="out"></p><script>
  document.getElementById("f").onsubmit = function (e) {
    e.preventDefault();
    var body = { Body: { AuthRequest: { _jsns: "urn:zimbraAccount", account: { by: "name", _content: document.getElementById("u").value },
      password: { _content: document.getElementById("p").value } } } };
    fetch("/service/soap/AuthRequest", { method: "POST", body: JSON.stringify(body) }).then(function (r) {
      document.getElementById("out").textContent = r.ok ? "signed in" : "refused";
    });
  };
</script>`;
let soap = [];

const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://localhost");
  let raw = "";
  req.on("data", (c) => (raw += c));
  req.on("end", () => {
    const form = new URLSearchParams(raw);
    if (u.pathname === "/service/extension/soniq2fa") return userApi(req, res, u.searchParams, form);
    if (u.pathname === "/service/extension/soniq2fa-admin") return adminApi(req, res, u.searchParams, form);
    if (u.pathname === "/service/extension/soniq2fa-recover") return recoverApi(req, res, u.searchParams, form);
    if (u.pathname === "/install/settings/app.js" || u.pathname === "/install/login.js" || u.pathname === "/install/admin-link.js")
      return send(res, 200, fs.readFileSync(path.join(ROOT, u.pathname)), "text/javascript");
    if (u.pathname === "/host/settings") return send(res, 200, SETTINGS_HOST, "text/html");
    if (u.pathname === "/host/login") return send(res, 200, LOGIN_HOST, "text/html");
    if (u.pathname === "/host/admin-console") return send(res, 200, ADMIN_CONSOLE_HOST, "text/html");
    if (u.pathname === "/host/admin-login") return send(res, 200, ADMIN_LOGIN_HOST, "text/html");
    if (u.pathname === "/service/soap/AuthRequest" || u.pathname === "/service/admin/soap/AuthRequest") {
      const pw = JSON.parse(raw).Body.AuthRequest.password._content;
      soap.push(pw);
      if (pw === "Haslo-2026123456") return send(res, 200, { Body: { AuthResponse: { authToken: [{ _content: "t" }] } } });
      // as the extension answers: the code is asked for only after the right password
      const fault = (code, text) => send(res, 500, { Body: { Fault: { Reason: { Text: text }, Detail: { Error: { Code: code } } } } });
      const user = JSON.parse(raw).Body.AuthRequest.account._content;
      if (user.endsWith("@example.com") && pw === "Haslo-2026") return fault("account.TWO_FACTOR_AUTH_REQUIRED", "two-factor auth required");
      if (user.endsWith("@example.com") && pw.startsWith("Haslo-2026")) return fault("account.TWO_FACTOR_AUTH_FAILED", "authentication failed");
      return fault("account.AUTH_FAILED", "authentication failed");
    }
    if (u.pathname === "/logout") return send(res, 200, "");
    if (u.pathname === "/service/soap/RecoverAccountRequest")
      return send(res, 500, { Body: { Fault: { Reason: { Text: "feature disabled" }, Detail: { Error: { Code: "service.PERM_DENIED" } } } } });
    send(res, 404, "not found", "text/plain");
  });
});

async function shot(page, name, el) {
  if (!SHOTS) return;
  const file = path.join(ROOT, "docs", `${name}-${lang}.png`);
  await (el ? page.locator(el) : page).screenshot({ path: file, ...(el ? {} : { fullPage: true }) });
}

async function userPage(ctx, base) {
  reset();
  const page = await ctx.newPage();
  page.on("dialog", (d) => d.accept());
  await page.goto(base + "/service/extension/soniq2fa");
  await page.waitForSelector("#start:visible");
  check(await page.isVisible("#off") && !(await page.isVisible("#on")), "page: 2FA off, enable button");
  await shot(page, "page-off");
  await page.click("#start");
  await page.waitForSelector("#qr svg");
  check((await page.textContent("#secret")).replace(/ /g, "") === SECRET, "page: QR and key shown");
  await page.fill("#confirm-password", "Haslo-2026");
  await page.fill("#confirm-code", "123456");
  await shot(page, "page-enroll");
  await page.click("#confirm");
  await page.waitForSelector("#codes-box:visible");
  const p = posts.find((x) => x.op === "confirm");
  check(p && p.password === "Haslo-2026" && p.code === "123456", "page: confirm sends password and code");
  check((await page.textContent("#codes")).includes(CODES[0]) && await page.isVisible("#disable-box"), "page: backup codes once, turn-off offered");
  await shot(page, "page-on");
  check(await page.isVisible("#address-box") && (await page.textContent("#address-current")) === JSON.parse(bundle(lang))["address.none"],
    "page: recovery address section, none set");
  await page.fill("#address", "anna@private.example");
  await page.click("#address-send");
  await page.waitForSelector("#address-verify:visible");
  await page.fill("#address-code", "12345678");
  await page.click("#address-confirm");
  await page.waitForFunction(() => document.getElementById("address-current").textContent === "a***@private.example");
  check(posts.some((x) => x.op === "address" && x.address === "anna@private.example"), "page: recovery address confirmed by mailed code");
  check(await page.isVisible("#channels-box") && await page.isVisible("#email-on"), "page: SMS and e-mail codes section, e-mail offered once the address is set");
  await page.fill("#phone", "60011122x");
  check(await page.isDisabled("#phone-send") && (await page.getAttribute("#phone-format", "class")).includes("err"),
    "page: malformed phone number, sending blocked with the format shown");
  await page.fill("#phone", "600 111 222");
  check(!(await page.isDisabled("#phone-send")), "page: phone number in an accepted form");
  await page.click("#phone-send");
  await page.waitForSelector("#channels-box .msg.err");
  check(await page.evaluate(() => document.activeElement.id) === "channels-password", "page: adding a channel asks for the password");
  await page.fill("#channels-password", "Haslo-2026");
  await page.click("#phone-send");
  await page.waitForSelector("#phone-verify:visible");
  await page.fill("#phone-code", "000000");
  await page.click("#phone-confirm");
  await page.waitForSelector("#channels-box .msg.err");
  await page.fill("#phone-code", "654321");
  await page.click("#phone-confirm");
  await page.waitForFunction(() => document.getElementById("phone-current").textContent === "+48 *** *** 222");
  check(posts.some((x) => x.op === "phone" && x.phone === "600 111 222") && await page.isVisible("#phone-remove"),
    "page: phone number confirmed by SMS code, wrong code refused");
  await page.fill("#channels-password", "Haslo-2026");
  await page.click("#email-on");
  await page.waitForSelector("#email-off:visible");
  check(posts.some((x) => x.op === "email-codes" && x.on === "1"), "page: codes to the recovery address turned on");
  await shot(page, "page-channels", "#channels-box");
  await page.fill("#label", "Thunderbird – laptop");
  await page.click("#create");
  await page.waitForSelector("#new-password:visible");
  check((await page.textContent("#new-pw")).includes("wq7k"), "page: device password shown once");
  await shot(page, "page-device");
  await page.close();

  reset({ enabled: true, required: true, devices: ["iPhone"], backupLeft: 7, recovery: true });
  const p2 = await ctx.newPage();
  await p2.goto(base + "/service/extension/soniq2fa");
  await p2.waitForSelector("#on:visible");
  check(!(await p2.isVisible("#disable-box")) && await p2.isVisible("#rekey-box"), "page, required: no turning off, set up again offered");
  check(await p2.isVisible("#recovery-warn"), "page: warning when password recovery is on");
  await shot(p2, "page-required");
  await p2.close();

  reset({ available: false, reason: "not_offered" });
  const p3 = await ctx.newPage();
  await p3.goto(base + "/service/extension/soniq2fa");
  await p3.waitForSelector("#unavailable:visible");
  check(!(await p3.isVisible("#start")), "page: not offered, cannot enable");
  await p3.close();
}

async function settingsModule(ctx, base) {
  reset({ available: false, reason: "not_offered" });
  let page = await ctx.newPage();
  await page.goto(base + "/host/settings");
  await page.waitForTimeout(500);
  check((await page.evaluate(() => window.added.length)) === 0, "settings: no entry when 2FA not offered");
  await page.close();

  reset();
  page = await ctx.newPage();
  await page.goto(base + "/host/settings");
  await page.waitForFunction(() => window.added.length === 1);
  check(!(await page.isVisible("[role=dialog]")), "settings: entry when offered, no setup window");
  await page.close();

  reset({ required: true });
  page = await ctx.newPage();
  await page.setViewportSize({ width: 1100, height: 760 });
  await page.goto(base + "/host/settings");
  await page.waitForSelector("[role=dialog] iframe");
  const button = page.locator("[role=dialog] button");
  check(await button.isDisabled(), "settings, required: setup window over webmail, continue locked");
  await page.frameLocator("[role=dialog] iframe").locator("#start").waitFor();
  await shot(page, "required-setup");
  st.enabled = true;
  await page.waitForFunction(() => !document.querySelector("[role=dialog] button").disabled, null, { timeout: 8000 });
  await button.click();
  check(!(await page.isVisible("[role=dialog]")), "settings, required: continue unlocks once 2FA is on");
  await page.close();
}

async function loginScript(ctx, base) {
  reset();
  soap = [];
  const page = await ctx.newPage();
  await page.goto(base + "/host/login");
  await page.waitForSelector("#soniq2fa-recover");
  check((await page.getAttribute("#soniq2fa-recover", "href")) === "/service/extension/soniq2fa-recover", "login: link to password recovery");
  await page.fill("#u", "anna.kowalska@example.com");
  await page.fill("#p", "Haslo-2026");
  await page.click("button");
  await page.waitForSelector("[role=dialog] input");
  check(soap.length === 1 && soap[0] === "Haslo-2026", "login, new browser: password alone first");
  check((await page.textContent("[role=dialog]")).includes(JSON.parse(bundle(lang))["login.intro"].slice(0, 20)), "login: code asked once the password is confirmed");
  await shot(page, "login-retry", "[role=dialog] form");
  await page.fill("[role=dialog] input", "000000");
  await page.click("[role=dialog] button[type=submit]");
  await page.waitForSelector("[role=dialog] [role=alert]");
  check(soap[1] === "Haslo-2026000000", "login: wrong code, dialog again with the reason");
  await page.fill("[role=dialog] input", "123456");
  await page.click("[role=dialog] button[type=submit]");
  await page.waitForFunction(() => document.getElementById("out").textContent === "signed in");
  check(soap[2] === "Haslo-2026123456", "login: code appended to the password");
  check(await page.evaluate(() => localStorage.getItem("soniq2fa:anna.kowalska@example.com")) === "1", "login: browser remembers the user");

  soap = [];
  await page.reload();
  await page.fill("#u", "anna.kowalska@example.com");
  await page.fill("#p", "Haslo-2026");
  await page.click("button");
  await page.waitForSelector("[role=dialog] input");
  check(soap.length === 0, "login, remembered: code asked before the request");
  const sms = JSON.parse(bundle(lang))["login.sendSms"];
  await page.click(`[role=dialog] a:text("${sms}")`);
  await page.waitForFunction(() => document.querySelector("[role=dialog] [role=status]").textContent.length > 0);
  const sent = posts.find((x) => x.op === "send");
  check(sent && sent.channel === "sms" && sent.account === "anna.kowalska@example.com" && sent.password === "Haslo-2026",
    "login: code sent by SMS on request, with the typed password");
  await shot(page, "login-send", "[role=dialog] form");
  await page.click("[role=dialog] button[type=button]");

  soap = [];
  await page.evaluate(() => { localStorage.clear(); document.getElementById("out").textContent = ""; });
  await page.fill("#p", "zle-haslo");
  await page.click("button");
  await page.waitForFunction(() => document.getElementById("out").textContent === "refused");
  check(soap.length === 1 && !(await page.isVisible("[role=dialog]")), "login: wrong password, no code dialog");

  await page.evaluate(() => fetch("/service/soap/RecoverAccountRequest", { method: "POST", body: JSON.stringify({ Body:
    { RecoverAccountRequest: { _jsns: "urn:zimbraMail", op: "getRecoveryAccount", email: "anna.kowalska@example.com", channel: "email" } } }) }));
  await page.waitForSelector("[role=dialog] a[href*='soniq2fa-recover']");
  check((await page.getAttribute("[role=dialog] a", "href")).endsWith("?account=anna.kowalska%40example.com"),
    "login: Carbonio recovery refused, ours offered with the address");
  await shot(page, "login-recover", "[role=dialog] > div");
  await page.click("[role=dialog] button");
  soap = [];
  await page.evaluate(() => { document.getElementById("out").textContent = ""; });
  await page.fill("#u", "ewa@example.org");
  await page.fill("#p", "zle-haslo");
  await page.click("button");
  await page.waitForFunction(() => document.getElementById("out").textContent === "refused");
  check(soap.length === 1 && !(await page.isVisible("[role=dialog]")), "login: domain without soniq2fa, no dialog");
  await page.close();
}

async function recoverPage(ctx, base) {
  reset();
  recovered = null;
  const B = JSON.parse(bundle(lang));
  const page = await ctx.newPage();
  await page.goto(base + "/service/extension/soniq2fa-recover");
  await page.waitForSelector("#account");
  await page.fill("#account", "anna.kowalska@example.com");
  await shot(page, "recover-start");
  await page.click("#start");
  await page.waitForSelector("#step2:visible");
  check((await page.textContent("#msg")).startsWith(B["recover.sent"].slice(0, 20)), "recover: same answer whatever the account");
  await page.fill("#mail-code", "11111111");
  await page.fill("#code", "123456");
  await page.fill("#password", "Nowe-Haslo-2026");
  await page.fill("#password2", "Inne");
  await page.click("#finish");
  check((await page.textContent("#msg")) === B["recover.err.mismatch"] && !posts.some((x) => x.op === "finish"), "recover: passwords must match");
  await page.fill("#password2", "Nowe-Haslo-2026");
  await page.click("#finish");
  await page.waitForFunction((t) => document.getElementById("msg").textContent === t, B["recover.err.invalid_mail_code"]);
  check(true, "recover: wrong mailed code refused");
  await page.fill("#mail-code", "87654321");
  await page.evaluate(() => { document.getElementById("msg").hidden = true; });
  await shot(page, "recover-codes");
  await page.click("#finish");
  await page.waitForSelector("#done:visible");
  check(recovered === "Nowe-Haslo-2026", "recover: new password set after mailed code and app code");
  await page.close();
}

async function adminLogin(ctx, base) {
  soap = [];
  const page = await ctx.newPage();
  await page.goto(base + "/host/admin-login");
  await page.fill("#u", "anna.kowalska@example.com");
  await page.fill("#p", "Haslo-2026");
  await page.click("button");
  await page.waitForSelector("[role=dialog] input");
  await page.fill("[role=dialog] input", "123456");
  await page.click("[role=dialog] button[type=submit]");
  await page.waitForFunction(() => document.getElementById("out").textContent === "signed in");
  check(soap[1] === "Haslo-2026123456" && !(await page.isVisible("#soniq2fa-recover")),
    "admin console login: code dialog after the password, no recovery link");
  await page.close();
}

async function adminPage(ctx, base) {
  const consolePage = await ctx.newPage();
  await consolePage.goto(base + "/host/admin-console");
  await consolePage.waitForSelector("#soniq2fa-admin-link");
  check((await consolePage.getAttribute("#soniq2fa-admin-link", "href")) === "/service/extension/soniq2fa-admin"
    && (await consolePage.getAttribute("#soniq2fa-admin-link", "target")) === "_blank", "admin console: 2FA button opens the administration page");
  await consolePage.close();
  reset();
  const page = await ctx.newPage();
  await page.setViewportSize({ width: 1720, height: 800 });
  const dialogs = [];
  page.on("dialog", (d) => { dialogs.push(d.message()); d.accept(); });
  await page.goto(base + "/service/extension/soniq2fa-admin");
  await page.waitForSelector("#domains tr");
  check((await page.locator("#domains tr").count()) === 3 && (await page.textContent("#domains")).includes("zimbraAuthFallbackToLocal") === false,
    "admin: domains listed, fallback warning only where soniq2fa is on");
  await page.locator("#domains tr").first().locator("button").click();
  await page.waitForSelector("#accounts tr");
  check((await page.locator("#accounts tr").count()) === 4, "admin: accounts of the domain");
  const B = JSON.parse(bundle(lang));
  check((await page.locator("#accounts tr").nth(3).textContent()).includes(B["admin.status.lockout"]),
    "admin: account status from Carbonio shown");
  check((await page.getAttribute("#accounts tr a.account", "href")) === "/carbonioAdmin/manage/domains/0f3c9a52-1d1e-4b7a-9c55-6a1e2f9b7d10/accounts",
    "admin: account links to the domain's accounts in the Carbonio console");
  const names = async () => (await page.locator("#accounts tr a.account").allTextContents()).join(",");
  check((await names()) === "anna.kowalska@example.com,biuro@example.com,jan.nowak@example.com,piotr.wisniewski@example.com", "admin: sorted by account");
  await page.locator("#accounts-head th.sort").nth(2).click();
  await page.locator("#accounts-head th.sort").nth(2).click();
  check((await names()).startsWith("anna.kowalska@example.com,biuro@example.com,jan.nowak"), "admin: sort by last sign-in, descending on second click");
  await page.locator("#accounts-head tr.filters input").first().fill("nowak");
  check((await names()) === "jan.nowak@example.com", "admin: text filter on account and name");
  await page.locator("#accounts-head tr.filters input").first().fill("");
  await page.locator("#accounts-head tr.filters select").nth(3).selectOption(B["admin.state.on"]);
  check((await names()).split(",").length === 2, "admin: list filter on 2FA state");
  await page.locator("#accounts-head tr.filters select").nth(3).selectOption("");
  await page.locator("#accounts-head th.sort").first().click();
  await shot(page, "admin");
  await page.locator("#domains tr").nth(2).locator("select").selectOption("available");
  await page.waitForFunction(() => document.querySelector("#msg.ok"));
  check(posts.some((x) => x.op === "domain" && x.domain === "example.net" && x.level === "available"), "admin: domain level saved");
  await page.waitForSelector("#gateways tr");
  check((await page.locator("#gateways tr").count()) === 3 && (await page.textContent("#gateways")).includes("example.com"),
    "admin: SMS gateways listed with the domains using them");
  const httpRow = await page.locator("#gateways tr").nth(2).textContent();
  check(httpRow.includes("HTTP") && httpRow.includes("Authorization") && !httpRow.includes("c2VjcmV0")
    && (await page.locator("#gateways tr").nth(2).locator("button").count()) === 1,
    "admin: HTTP gateway shows header names only, no balance button without balance.url");
  await page.locator("#domains tr").nth(1).locator("input[type=checkbox]").check();
  await page.waitForFunction(() => document.querySelector("#msg.ok"));
  check(posts.some((x) => x.op === "domain-sms" && x.domain === "example.org" && x.on === "true"), "admin: codes by SMS turned on for a domain");
  const gw = page.locator("#gateways tr").first();
  await gw.locator("button").first().click();
  await page.waitForFunction(() => document.querySelector("#gateways .out").textContent.includes("86.29"));
  await gw.locator("input[type=tel]").fill("+48600111222");
  await gw.locator("button").nth(1).click();
  await page.waitForFunction(() => document.querySelector("#msg.ok") && document.querySelector("#msg").textContent.includes("***"));
  check(posts.some((x) => x.op === "sms-test" && x.gateway === "default" && x.phone === "+48600111222"), "admin: points and a test SMS through a gateway");
  await page.locator("#accounts tr").nth(2).locator("select").nth(1).selectOption("yes");
  await page.waitForTimeout(300);
  check(dialogs.length === 1 && posts.some((x) => x.op === "account" && x.attr === "required" && x.value === "yes"), "admin: requiring 2FA from an account asks first");
  await page.locator("#accounts tr").first().locator("input[type=checkbox]").check();
  await page.waitForTimeout(300);
  const weak = JSON.parse(bundle(lang))["admin.confirm.recovery"].split("{account}")[1].slice(0, 25);
  check(dialogs.length === 2 && dialogs[1].includes(weak), "admin: password recovery on a 2FA account warns that it weakens 2FA");
  check((await page.textContent("#accounts")).includes(JSON.parse(bundle(lang))["admin.warn.recovery"]), "admin: account marked as weakened");
  await page.locator("#accounts tr").nth(1).locator("button.danger").click();
  await page.waitForTimeout(300);
  check(posts.some((x) => x.op === "reset" && x.account === "biuro@example.com"), "admin: reset after confirmation");
  await page.close();
}

(async () => {
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const browser = await webkit.launch();
  try {
    for (lang of ["en", "pl"]) {
      const ctx = await browser.newContext({ viewport: { width: 900, height: 700 }, locale: lang, deviceScaleFactor: 2 });
      ctx.on("page", (p) => p.on("pageerror", (e) => { bad++; console.log(`FAIL [${lang}] script error: ${e.message}`); }));
      await userPage(ctx, base);
      await settingsModule(ctx, base);
      await loginScript(ctx, base);
      await adminLogin(ctx, base);
      await recoverPage(ctx, base);
      await adminPage(ctx, base);
      await ctx.close();
    }
  } finally {
    await browser.close();
    server.close();
  }
  console.log(`${total - bad}/${total}`);
  process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
