// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
package pl.soniqsoft.soniq2fa;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Second-factor codes sent by SMS or to the verified recovery address, as an alternative to the app.
 *
 * Per account the channels are values of zimbraTwoFactorAuthTrustedDevices (multi-valued, unused by Carbonio CE, which
 * has no 2FA; immutable, so users cannot set it through SOAP): "sms:+48600111222" for a phone number confirmed with an
 * SMS code, "email" when login codes may go to the recovery address.
 *
 * SMS gateways are configured on the server in GATEWAY_FILE (root:zextras 0640); without the file SMS is off.
 * The default gateway:
 *   sms.provider=smsapi
 *   sms.token=<OAuth token from the SMSAPI panel>
 *   sms.from=<sender name registered in SMSAPI; empty: the account's default>
 *   sms.url=https://api.smsapi.pl/sms.do   (optional)
 *   sms.maxPerHour=200                     (optional, per gateway)
 *   sms.countries=+48                      (optional, allowed number prefixes, comma-separated; against SMS pumping)
 * Any HTTP SMS gateway instead of SMSAPI (sms.provider=http):
 *   sms.http.url=<address; may contain {to} {to_digits} {text} {from}, URL-encoded>
 *   sms.http.method=POST                   (or GET)
 *   sms.http.header.<Name>=<value>         (e.g. Authorization, Content-Type; never shown on the admin page)
 *   sms.http.body=<template with {to} {to_digits} {text} {from}>
 *   sms.http.encoding=form                 (form: URL-encoded values, json: JSON string escapes, none)
 *   sms.http.success.status=200,201,202    (accepted HTTP codes)
 *   sms.http.success.match=<regex>         (optional, must be found in the answer)
 *   sms.http.balance.url=<address>, sms.http.balance.match=<regex, group 1 = balance>   (optional, admin page)
 * Any key can be overridden for one mail domain as domain.<domain>.sms.<key>, e.g. domain.example.com.sms.from=Example;
 * a domain with its own domain.<domain>.sms.token (SMSAPI) or sms.http.url has its own gateway (own account, own hourly
 * limit), the others use the default one. Whether a domain may send SMS at all is set on the domain (flag "sms" of its mechanism, see
 * Soniq2faPage.smsEnabled).
 * No Carbonio classes, so the self-test runs without a mailbox.
 */
final class Channels {
    static final String A_CHANNELS = "zimbraTwoFactorAuthTrustedDevices";
    static final String EMAIL = "email", SMS_PREFIX = "sms:", RECOVERY_PREFIX = "recovery:";
    static final Path GATEWAY_FILE = Path.of("/opt/zextras/lib/ext/soniq2fa/soniq2fa.properties");
    static final String DEFAULT = "default";
    private static final Map<String, long[]> HOURS = new java.util.concurrent.ConcurrentHashMap<>();

    private Channels() {
    }

    /** The confirmed phone number, or null. */
    static String phone(String[] values) {
        for (String v : values) if (v.startsWith(SMS_PREFIX)) return v.substring(SMS_PREFIX.length());
        return null;
    }

    static boolean email(String[] values) {
        for (String v : values) if (EMAIL.equals(v)) return true;
        return false;
    }

    /**
     * A mobile number in international form, or null. Accepted: +48600111222, 0048600111222, 600111222 (Polish, nine
     * digits); spaces and dashes between digits are ignored, nothing else. A Polish number must be a mobile one
     * (9 digits starting with 4-8); other countries: 8-15 digits after the country code, as E.164 allows.
     */
    static String normalizePhone(String input) {
        if (input == null) return null;
        String s = input.trim().replaceAll("(?<=[0-9])[ -](?=[0-9])", "");
        if (s.matches("00[1-9][0-9]{7,14}")) s = "+" + s.substring(2);
        else if (s.matches("[0-9]{9}")) s = "+48" + s;
        if (!s.matches("\\+[1-9][0-9]{7,14}")) return null;
        return !s.startsWith("+48") || s.matches("\\+48[4-8][0-9]{8}") ? s : null;
    }

    /** The number starts with one of the prefixes in sms.countries of the domain's gateway (default +48). */
    static boolean allowedCountry(String domain, String phone) {
        return allowedCountry(gateway(domain), phone);
    }

    static boolean allowedCountry(Properties p, String phone) {
        for (String c : p.getProperty("sms.countries", "+48").split(","))
            if (!c.isBlank() && phone.startsWith(c.trim())) return true;
        return false;
    }

    /** "+48 *** *** 222": enough for the user to recognise the number. */
    static String maskPhone(String phone) {
        if (phone == null || phone.length() < 6) return "";
        String cc = phone.startsWith("+48") ? "+48" : phone.substring(0, 3);
        return cc + " *** *** " + phone.substring(phone.length() - 3);
    }

    /** The file is there but the mailbox (user zextras) cannot read it: SMS is then hidden for everyone. */
    static boolean gatewayUnreadable() {
        return Files.exists(GATEWAY_FILE) && !Files.isReadable(GATEWAY_FILE);
    }

    /** The whole file, every gateway; empty without it. */
    static Properties file() {
        Properties p = new Properties();
        if (!Files.isReadable(GATEWAY_FILE)) return p;
        try (InputStream in = Files.newInputStream(GATEWAY_FILE)) {
            p.load(in);
        } catch (IOException e) {
            return new Properties();
        }
        return p;
    }

    /**
     * The gateway of a mail domain as sms.* keys: the default ones, overridden by domain.<domain>.sms.*. "gateway.name"
     * is the domain when it has its own sms.token, else DEFAULT.
     */
    static Properties gateway(Properties file, String domain) {
        Properties p = new Properties();
        for (String k : file.stringPropertyNames()) if (k.startsWith("sms.")) p.setProperty(k, file.getProperty(k));
        String prefix = "domain." + (domain == null ? "" : domain.toLowerCase(java.util.Locale.ROOT)) + ".";
        boolean own = false;
        for (String k : file.stringPropertyNames()) {
            if (!k.startsWith(prefix + "sms.")) continue;
            p.setProperty(k.substring(prefix.length()), file.getProperty(k));
            own |= k.equals(prefix + "sms.token") || k.equals(prefix + "sms.http.url");
        }
        p.setProperty("gateway.name", own ? domain.toLowerCase(java.util.Locale.ROOT) : DEFAULT);
        return p;
    }

    static Properties gateway(String domain) {
        return gateway(file(), domain);
    }

    static boolean configured(Properties p) {
        String provider = p.getProperty("sms.provider", "").trim();
        if ("http".equals(provider)) return !p.getProperty("sms.http.url", "").isBlank();
        return "smsapi".equals(provider) && !p.getProperty("sms.token", "").isBlank();
    }

    static boolean http(Properties p) {
        return "http".equals(p.getProperty("sms.provider", "").trim());
    }

    /** The domain's gateway can send (whether the domain may use it is decided by the caller). */
    static boolean smsAvailable(String domain) {
        return configured(gateway(domain));
    }

    /** Gateways in the file: DEFAULT when it has a token, and every domain with its own sms.token. */
    static List<String> gatewayNames(Properties file) {
        List<String> names = new ArrayList<>();
        if (!file.getProperty("sms.token", "").isBlank() || !file.getProperty("sms.http.url", "").isBlank()) names.add(DEFAULT);
        for (String k : new java.util.TreeSet<>(file.stringPropertyNames())) {
            if (!k.startsWith("domain.")) continue;
            String name = k.endsWith(".sms.token") ? k.substring(7, k.length() - 10)
                    : k.endsWith(".sms.http.url") ? k.substring(7, k.length() - 13) : null;
            if (name != null && !names.contains(name)) names.add(name);
        }
        return names;
    }

    /** At most sms.maxPerHour messages an hour per gateway, whatever the accounts. */
    static boolean mayText(Properties p, long now) {
        int max = Integer.parseInt(p.getProperty("sms.maxPerHour", "200").trim());
        long[] h = HOURS.computeIfAbsent(p.getProperty("gateway.name", DEFAULT), k -> new long[]{0, 0});
        synchronized (h) {
            if (now - h[0] > 3_600_000) {
                h[0] = now;
                h[1] = 0;
            }
            if (h[1] >= max) return false;
            h[1]++;
            return true;
        }
    }

    /** Messages sent through a gateway in the current hour. */
    static long sentThisHour(String gatewayName, long now) {
        long[] h = HOURS.get(gatewayName);
        if (h == null) return 0;
        synchronized (h) {
            return now - h[0] > 3_600_000 ? 0 : h[1];
        }
    }

    // ---- any HTTP gateway (sms.provider=http) ----

    /** Values for the templates: {to} +48600111222, {to_digits} 48600111222, {text}, {from}. */
    static Map<String, String> vars(Properties p, String phone, String text) {
        return Map.of("to", phone, "to_digits", phone.substring(1), "text", text, "from", p.getProperty("sms.from", "").trim());
    }

    /** The template with {name} replaced by the values, each encoded: form (URL), json (string escapes) or none. */
    static String fill(String template, Map<String, String> vars, String encoding) {
        StringBuilder b = new StringBuilder();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\\{(to|to_digits|text|from)\\}").matcher(template);
        while (m.find()) m.appendReplacement(b, java.util.regex.Matcher.quoteReplacement(encode(vars.get(m.group(1)), encoding)));
        m.appendTail(b);
        return b.toString();
    }

    static String encode(String v, String encoding) {
        if ("json".equals(encoding)) {
            StringBuilder b = new StringBuilder();
            for (char c : v.toCharArray()) {
                if (c == '"' || c == '\\') b.append('\\').append(c);
                else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                else b.append(c);
            }
            return b.toString();
        }
        if ("none".equals(encoding)) return v;
        return URLEncoder.encode(v, StandardCharsets.UTF_8);
    }

    static HttpRequest httpRequest(Properties p, String phone, String text) {
        Map<String, String> v = vars(p, phone, text);
        String url = fill(p.getProperty("sms.http.url").trim(), v, "form");
        String body = fill(p.getProperty("sms.http.body", ""), v, p.getProperty("sms.http.encoding", "form").trim());
        HttpRequest.Builder r = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(20));
        headers(p, r);
        if ("GET".equalsIgnoreCase(p.getProperty("sms.http.method", "POST").trim())) r.GET();
        else r.POST(HttpRequest.BodyPublishers.ofString(body));
        return r.build();
    }

    private static void headers(Properties p, HttpRequest.Builder r) {
        for (String k : p.stringPropertyNames())
            if (k.startsWith("sms.http.header.")) r.header(k.substring("sms.http.header.".length()), p.getProperty(k).trim());
    }

    /** Names of the configured headers, for the admin page (their values may be secrets). */
    static List<String> headerNames(Properties p) {
        List<String> n = new ArrayList<>();
        for (String k : new java.util.TreeSet<>(p.stringPropertyNames()))
            if (k.startsWith("sms.http.header.")) n.add(k.substring("sms.http.header.".length()));
        return n;
    }

    static boolean httpAccepted(Properties p, int status, String body) {
        boolean code = false;
        for (String c : p.getProperty("sms.http.success.status", "200,201,202").split(","))
            code |= c.trim().equals(String.valueOf(status));
        String match = p.getProperty("sms.http.success.match", "").trim();
        return code && (match.isEmpty() || java.util.regex.Pattern.compile(match).matcher(body == null ? "" : body).find());
    }

    /** At most 200 characters of a gateway's answer, without digit runs that could be a phone number. */
    static String redact(String body) {
        String b = body == null ? "" : body.replaceAll("\\s+", " ").replaceAll("\\+?[0-9]{7,}", "…");
        return b.length() > 200 ? b.substring(0, 200) + "…" : b;
    }

    /** The address without query and user info, for the admin page (a query may carry an API key). */
    static String publicUrl(Properties p) {
        String u = http(p) ? p.getProperty("sms.http.url", "") : p.getProperty("sms.url", "https://api.smsapi.pl/sms.do");
        try {
            URI x = URI.create(u.trim().replaceAll("\\{[a-z_]+\\}", "x"));
            return x.getScheme() + "://" + x.getHost() + (x.getPort() > 0 ? ":" + x.getPort() : "") + (x.getPath() == null ? "" : x.getPath());
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    /** Whether the admin page can ask for the balance: SMSAPI always, other gateways with sms.http.balance.url. */
    static boolean hasBalance(Properties p) {
        return !http(p) || !p.getProperty("sms.http.balance.url", "").isBlank();
    }

    /** Balance or points left on the gateway's account; throws with the answer when it cannot be read. */
    static String balance(Properties p) throws IOException, InterruptedException {
        if (!http(p)) return smsapiPoints(p);
        HttpRequest.Builder r = HttpRequest.newBuilder(URI.create(p.getProperty("sms.http.balance.url", "").trim()))
                .timeout(Duration.ofSeconds(15)).GET();
        headers(p, r);
        HttpResponse<String> resp = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()
                .send(r.build(), HttpResponse.BodyHandlers.ofString());
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(p.getProperty("sms.http.balance.match", "([0-9.]+)").trim()).matcher(resp.body());
        if (resp.statusCode() / 100 != 2 || !m.find()) throw new IOException("balance not read: HTTP " + resp.statusCode() + " " + redact(resp.body()));
        return m.group(m.groupCount() >= 1 ? 1 : 0);
    }

    /** Points left on the SMSAPI account of a gateway (GET /profile); throws with the gateway's answer on refusal. */
    static String smsapiPoints(Properties p) throws IOException, InterruptedException {
        String url = p.getProperty("sms.url", "https://api.smsapi.pl/sms.do").trim().replaceFirst("/sms\\.do$", "/profile");
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(15))
                .header("Authorization", "Bearer " + p.getProperty("sms.token", "").trim()).GET().build();
        HttpResponse<String> resp = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()
                .send(req, HttpResponse.BodyHandlers.ofString());
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"points\"\\s*:\\s*([0-9.]+)").matcher(resp.body());
        if (resp.statusCode() != 200 || !m.find()) throw new IOException("SMSAPI refused: HTTP " + resp.statusCode() + " " + refusal(resp.body()));
        return m.group(1);
    }

    /** Form body of an SMSAPI sms.do request. */
    static String smsapiBody(String phone, String text, String from) {
        List<String> f = new ArrayList<>();
        for (Map.Entry<String, String> e : Map.of("to", phone.substring(1), "message", text, "format", "json",
                "encoding", "utf-8", "normalize", "1").entrySet())
            f.add(e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
        if (from != null && !from.isBlank()) f.add("from=" + URLEncoder.encode(from.trim(), StandardCharsets.UTF_8));
        return String.join("&", f);
    }

    /** Sends one SMS through the domain's gateway (SMSAPI); throws with the gateway's answer when it is refused. */
    static void sendSms(String domain, String phone, String text) throws IOException, InterruptedException {
        sendSms(gateway(domain), phone, text);
    }

    static void sendSms(Properties p, String phone, String text) throws IOException, InterruptedException {
        if (!configured(p)) throw new IOException("SMS gateway '" + p.getProperty("gateway.name") + "' not configured in " + GATEWAY_FILE);
        if (!mayText(p, System.currentTimeMillis()))
            throw new IOException("hourly SMS limit of gateway '" + p.getProperty("gateway.name") + "' reached (sms.maxPerHour)");
        if (http(p)) {
            HttpResponse<String> resp = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()
                    .send(httpRequest(p, phone, text), HttpResponse.BodyHandlers.ofString());
            if (!httpAccepted(p, resp.statusCode(), resp.body()))
                throw new IOException("gateway refused: HTTP " + resp.statusCode() + " " + redact(resp.body()));
            return;
        }
        HttpRequest req = HttpRequest.newBuilder(URI.create(p.getProperty("sms.url", "https://api.smsapi.pl/sms.do").trim()))
                .timeout(Duration.ofSeconds(20))
                .header("Authorization", "Bearer " + p.getProperty("sms.token").trim())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(smsapiBody(phone, text, p.getProperty("sms.from"))))
                .build();
        HttpResponse<String> resp = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()
                .send(req, HttpResponse.BodyHandlers.ofString());
        if (!smsapiAccepted(resp.statusCode(), resp.body()))
            throw new IOException("SMSAPI refused: HTTP " + resp.statusCode() + " " + refusal(resp.body()));
    }

    /**
     * SMSAPI answers 200 with {"count":1,"list":[{..., "status":"QUEUE", "error":null}]} on success and
     * {"error":<n>,"message":...} otherwise; only a numeric error code means a refusal.
     */
    static boolean smsapiAccepted(int status, String body) {
        return status == 200 && body != null && body.contains("\"list\"") && !body.matches("(?s).*\"error\"\\s*:\\s*[0-9].*");
    }

    /** Error code and message of a refusal, without the rest of the answer (it repeats the recipient's number). */
    static String refusal(String body) {
        java.util.regex.Matcher e = java.util.regex.Pattern.compile("\"error\"\\s*:\\s*([0-9]+)").matcher(body == null ? "" : body);
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"message\"\\s*:\\s*\"([^\"]{0,200})\"").matcher(body == null ? "" : body);
        return "error " + (e.find() ? e.group(1) : "?") + ": " + (m.find() ? m.group(1) : "");
    }

    private static Properties withUrl(Properties p, String url) {
        Properties c = (Properties) p.clone();
        c.setProperty("sms.http.url", url);
        return c;
    }

    static void selftest() {
        check("+48600111222".equals(normalizePhone("+48600111222")) && "+48600111222".equals(normalizePhone("0048600111222"))
                && "+48600111222".equals(normalizePhone("600111222")), "phone: the three accepted forms");
        check("+48600111222".equals(normalizePhone("600 111 222")) && "+48600111222".equals(normalizePhone("+48 600-111-222")),
                "phone: spaces and dashes between digits");
        check("+420601234567".equals(normalizePhone("00420 601 234 567")), "phone: 00 prefix, other country");
        for (String bad : new String[]{"", "12345", "+48abc", "abc600111222", "600111222x", "(600) 111 122", "600.111.122",
                "+48 600 111 12", "+4860011122233", "+48225551234", "+48195111222", "0600111222", "+0600111222", "48600111222",
                "--600111222", "x"})
            check(normalizePhone(bad) == null, "phone: reject '" + bad + "'");
        check("+48600111222".equals(normalizePhone(" +48 600 111 222 ")), "phone: outer spaces trimmed");
        check("+48 *** *** 222".equals(maskPhone("+48600111222")), "phone mask");
        String[] v = {"email", "sms:+48600111222"};
        check("+48600111222".equals(phone(v)) && email(v) && phone(new String[0]) == null && !email(new String[0]), "channels");
        String b = smsapiBody("+48600111222", "Kod: 123 456", "SoniqSoft");
        check(b.contains("to=48600111222") && b.contains("message=Kod%3A+123+456") && b.contains("format=json")
                && b.contains("from=SoniqSoft"), "smsapi body");
        check(!smsapiBody("+48600111222", "x", "").contains("from="), "smsapi body without sender");
        check(smsapiAccepted(200, "{\"count\":1,\"list\":[{\"id\":\"1\",\"status\":\"QUEUE\"}]}"), "smsapi accepted");
        check(smsapiAccepted(200, "{\"count\":1,\"list\":[{\"id\":\"6A\",\"points\":0.17,\"status\":\"QUEUE\",\"error\":null,\"idx\":null}]}"),
                "smsapi accepted, as sent on 2026-10-12 (error:null in the list)");
        check(!smsapiAccepted(200, "{\"error\":14,\"message\":\"Invalid from field\"}"), "smsapi refused, invalid sender");
        check("error 13: Invalid numbers".equals(refusal("{\"invalid_numbers\":[{\"number\":\"48600111222\"}],\"error\":13,\"message\":\"Invalid numbers\"}")),
                "smsapi refusal logged without the number");
        check(!smsapiAccepted(200, "{\"error\":101,\"message\":\"Authorization failed\"}") && !smsapiAccepted(401, "{}"), "smsapi refused");
        java.util.Properties p = new java.util.Properties();
        check(allowedCountry(p, "+48600111222") && !allowedCountry(p, "+420601234567"), "default country +48");
        p.setProperty("sms.countries", "+48, +420");
        check(allowedCountry(p, "+420601234567") && !allowedCountry(p, "+44700900123"), "configured countries");
        p.setProperty("sms.maxPerHour", "2");
        p.setProperty("gateway.name", "t1");
        check(mayText(p, 1) && mayText(p, 2) && !mayText(p, 3) && mayText(p, 3_700_000), "gateway SMS limit");
        Properties other = (Properties) p.clone();
        other.setProperty("gateway.name", "t2");
        check(mayText(other, 3), "limit counted per gateway");
        Properties f = new Properties();
        f.setProperty("sms.provider", "smsapi");
        f.setProperty("sms.token", "T0");
        f.setProperty("sms.from", "Default");
        f.setProperty("domain.example.com.sms.token", "T1");
        f.setProperty("domain.example.com.sms.from", "Example");
        f.setProperty("domain.example.org.sms.from", "Org");
        Properties com = gateway(f, "Example.com"), org = gateway(f, "example.org"), net = gateway(f, "example.net");
        check("T1".equals(com.getProperty("sms.token")) && "Example".equals(com.getProperty("sms.from"))
                && "example.com".equals(com.getProperty("gateway.name")) && configured(com), "domain with its own gateway");
        check("T0".equals(org.getProperty("sms.token")) && "Org".equals(org.getProperty("sms.from"))
                && DEFAULT.equals(org.getProperty("gateway.name")), "domain overriding the sender on the default gateway");
        check("T0".equals(net.getProperty("sms.token")) && DEFAULT.equals(net.getProperty("gateway.name")), "domain on the default gateway");
        check(List.of(DEFAULT, "example.com").equals(gatewayNames(f)), "gateway names");
        check(!configured(gateway(new Properties(), "example.com")), "no file, no gateway");

        // any HTTP gateway: a Twilio-like form POST and a JSON one, without sending anything
        Properties tw = new Properties();
        tw.setProperty("sms.provider", "http");
        tw.setProperty("sms.from", "+15005550006");
        tw.setProperty("sms.http.url", "https://api.example.com/2010-04-01/Accounts/AC1/Messages.json");
        tw.setProperty("sms.http.header.Authorization", "Basic c2VjcmV0");
        tw.setProperty("sms.http.header.Content-Type", "application/x-www-form-urlencoded");
        tw.setProperty("sms.http.body", "To={to}&From={from}&Body={text}");
        tw.setProperty("sms.http.success.status", "201");
        tw.setProperty("sms.http.success.match", "\"status\"\\s*:\\s*\"queued\"");
        HttpRequest twr = httpRequest(tw, "+48600111222", "Code: 123 456 & more");
        check(configured(tw) && "POST".equals(twr.method()) && twr.headers().firstValue("Authorization").orElse("").equals("Basic c2VjcmV0"),
                "http gateway: method and headers");
        check("To=%2B48600111222&From=%2B15005550006&Body=Code%3A+123+456+%26+more".equals(
                fill(tw.getProperty("sms.http.body"), vars(tw, "+48600111222", "Code: 123 456 & more"), "form")), "http gateway: form body");
        check(httpAccepted(tw, 201, "{\"sid\":\"SM1\",\"status\":\"queued\"}") && !httpAccepted(tw, 201, "{\"status\":\"failed\"}")
                && !httpAccepted(tw, 400, "{\"status\":\"queued\"}"), "http gateway: success by code and match");
        check("{\"phone\":\"48600111222\",\"text\":\"a \\\"b\\\" \\u000a\"}".equals(
                fill("{\"phone\":\"{to_digits}\",\"text\":\"{text}\"}", vars(tw, "+48600111222", "a \"b\" \n"), "json")), "http gateway: json escapes");
        check("https://api.example.com/send".equals(publicUrl(withUrl(tw, "https://api.example.com/send?key=SECRET&to={to}"))),
                "http gateway: address shown without the query");
        check(!redact("{\"to\":\"+48600111222\",\"error\":\"x\"}").contains("600111222"), "http gateway: answer logged without the number");
        check(List.of("Authorization", "Content-Type").equals(headerNames(tw)) && !hasBalance(tw), "http gateway: header names, no balance");
        Properties f2 = new Properties();
        f2.setProperty("domain.example.net.sms.provider", "http");
        f2.setProperty("domain.example.net.sms.http.url", "https://sms.example.net/send");
        check(List.of("example.net").equals(gatewayNames(f2)) && "example.net".equals(gateway(f2, "example.net").getProperty("gateway.name"))
                && configured(gateway(f2, "example.net")), "http gateway as a domain's own gateway");
    }

    private static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("selftest failed: " + name);
    }
}
