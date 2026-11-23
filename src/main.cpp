// ESPHole32 - a Pi-hole style DNS ad blocker for the ESP32-WROOM-32 (no PSRAM).
//
// How it works:
//   * Devices send DNS lookups to this board (UDP port 53).
//   * The domain (and each parent domain) is hashed and looked up in a sorted
//     table of 40-bit hashes stored in a dedicated flash partition.
//   * Blocked  -> reply 0.0.0.0 / :: immediately.
//   * Allowed  -> forward to the upstream DNS server and relay the answer back.
//
// Blocklists are built on a PC with tools/build_blocklist.py and uploaded from
// the web dashboard (or flashed with esptool).

#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <ESPmDNS.h>
#include <Preferences.h>
#include <LittleFS.h>
#include <esp_partition.h>
#include <lwip/sockets.h>
#include <vector>

#include "dnslogic.h"
#include "web_ui.h"

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------
#define FW_VERSION        "1.0.3"
#define SETUP_AP_SSID     "ESPHole32-Setup"
#define SETUP_AP_PASS     "esphole32"       // WPA2 password for the setup hotspot
#define BOOT_BUTTON_PIN   0                 // hold BOOT for 10 s to wipe Wi-Fi settings
#define MAX_LIST_ENTRIES  400               // per custom list
#define LOG_SIZE          80                // recent queries kept in RAM
#define MAX_CLIENTS       24
#define MAX_PENDING       32                // in-flight upstream queries
#define UPSTREAM_RETRY_MS 1000              // try secondary upstream after this
#define UPSTREAM_GIVEUP_MS 2500

struct Config {
  String ssid, pass, admin, host, ip, gw, mask, up1, up2;
} cfg;

Preferences prefs;
WebServer server(80);
DNSServer portalDns;
bool portalMode = false;

// ---------------------------------------------------------------------------
// Blocklist in flash
// ---------------------------------------------------------------------------
static const esp_partition_t* blPart = nullptr;
static volatile uint32_t blCount = 0;
static volatile bool blReady = false;

static bool blReadEntry(uint32_t i, uint8_t* out) {
  return esp_partition_read(blPart, dns::BL_HEADER + (size_t)i * dns::BL_ENTRY, out, 5) == ESP_OK;
}

static bool blContains(uint64_t h) {
  if (!blReady || !blPart) return false;
  return dns::sortedContains(blCount, h, blReadEntry);
}

static void loadBlocklist() {
  blReady = false;
  blCount = 0;
  if (!blPart) return;
  uint8_t hdr[dns::BL_HEADER];
  if (esp_partition_read(blPart, 0, hdr, sizeof hdr) != ESP_OK) return;
  long c = dns::parseHeader(hdr, blPart->size);
  if (c < 0) { Serial.println("[blocklist] none installed yet"); return; }
  blCount = (uint32_t)c;
  blReady = true;
  Serial.printf("[blocklist] %u domains loaded\n", (unsigned)blCount);
}

static uint32_t blCapacity() {
  return blPart ? (blPart->size - dns::BL_HEADER) / dns::BL_ENTRY : 0;
}

// ---------------------------------------------------------------------------
// Custom block / allow lists (stored in LittleFS, kept in RAM)
// ---------------------------------------------------------------------------
static std::vector<String> blockList, allowList;
static SemaphoreHandle_t listMutex;

static bool inList(const std::vector<String>& l, const char* s) {
  for (auto& e : l) if (e.equals(s)) return true;
  return false;
}

static void loadList(const char* path, std::vector<String>& l) {
  l.clear();
  File f = LittleFS.open(path, "r");
  if (!f) return;
  while (f.available() && l.size() < MAX_LIST_ENTRIES) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length()) l.push_back(line);
  }
  f.close();
}

static void saveList(const char* path, const std::vector<String>& l) {
  File f = LittleFS.open(path, "w");
  if (!f) return;
  for (auto& e : l) { f.print(e); f.print('\n'); }
  f.close();
}

// Normalise user input like "*.ads.com", "||ads.com^", "ADS.com." -> "ads.com"
static String cleanDomain(String d) {
  d.trim();
  d.toLowerCase();
  if (d.startsWith("||")) d = d.substring(2);
  if (d.startsWith("*.")) d = d.substring(2);
  if (d.startsWith("http://")) d = d.substring(7);
  if (d.startsWith("https://")) d = d.substring(8);
  int slash = d.indexOf('/');
  if (slash >= 0) d = d.substring(0, slash);
  while (d.endsWith("^") || d.endsWith(".")) d.remove(d.length() - 1);
  if (d.length() == 0 || d.length() > 200) return "";
  for (size_t i = 0; i < d.length(); i++) {
    char c = d[i];
    if (!(isalnum((unsigned char)c) || c == '-' || c == '.' || c == '_')) return "";
  }
  return d;
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------
enum Verdict : uint8_t { V_ALLOW = 0, V_BLOCK_LIST = 1, V_BLOCK_CUSTOM = 2, V_ALLOW_CUSTOM = 3, V_PAUSED = 4 };

struct ClientStat { uint32_t ip, queries, blocked, lastMs; };
struct LogEntry { uint32_t ms, ip; uint16_t qtype; uint8_t verdict; char name[72]; };

static portMUX_TYPE statMux = portMUX_INITIALIZER_UNLOCKED;
static ClientStat clients[MAX_CLIENTS];
static LogEntry logRing[LOG_SIZE];
static uint16_t logHead = 0, logCount = 0;
static uint32_t stTotal = 0, stBlocked = 0, stForwarded = 0, stFailed = 0;
static float stLatencyMs = 0;

static void recordQuery(uint32_t ip, const char* name, uint16_t qtype, uint8_t verdict) {
  bool blocked = verdict == V_BLOCK_LIST || verdict == V_BLOCK_CUSTOM;
  uint32_t now = millis();
  portENTER_CRITICAL(&statMux);
  stTotal++;
  if (blocked) stBlocked++;
  int slot = -1, oldest = 0;
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i].ip == ip) { slot = i; break; }
    if (clients[i].ip == 0 && slot < 0) slot = i;
    if (clients[i].lastMs < clients[oldest].lastMs) oldest = i;
  }
  if (slot < 0 || (clients[slot].ip != ip && clients[slot].ip != 0)) slot = oldest;
  if (clients[slot].ip != ip) clients[slot] = {ip, 0, 0, 0};
  clients[slot].queries++;
  if (blocked) clients[slot].blocked++;
  clients[slot].lastMs = now;
  LogEntry& e = logRing[logHead];
  e.ms = now; e.ip = ip; e.qtype = qtype; e.verdict = verdict;
  strncpy(e.name, name, sizeof e.name - 1);
  e.name[sizeof e.name - 1] = 0;
  logHead = (logHead + 1) % LOG_SIZE;
  if (logCount < LOG_SIZE) logCount++;
  portEXIT_CRITICAL(&statMux);
}

// ---------------------------------------------------------------------------
// Blocking decision
// ---------------------------------------------------------------------------
static volatile bool pausedForever = false;
static volatile uint32_t pauseUntil = 0;

static bool isPaused() {
  if (pausedForever) return true;
  return pauseUntil != 0 && (int32_t)(pauseUntil - millis()) > 0;
}

static uint8_t classify(const char* name) {
  if (!*name) return V_ALLOW;
  if (isPaused()) return V_PAUSED;
  bool allow = false, custom = false;
  xSemaphoreTake(listMutex, portMAX_DELAY);
  allow = dns::anySuffix(name, [](const char* s) { return inList(allowList, s); });
  if (!allow) custom = dns::anySuffix(name, [](const char* s) { return inList(blockList, s); });
  xSemaphoreGive(listMutex);
  if (allow) return V_ALLOW_CUSTOM;
  if (custom) return V_BLOCK_CUSTOM;
  if (dns::anySuffix(name, [](const char* s) { return blContains(dns::fnv40(s)); })) return V_BLOCK_LIST;
  return V_ALLOW;
}

// ---------------------------------------------------------------------------
// DNS server task (UDP 53) with upstream forwarding
// ---------------------------------------------------------------------------
struct Pending {
  bool used;
  uint16_t newId, origId;
  sockaddr_in client;
  uint32_t t;
  uint8_t tries;
  uint16_t qlen;
  uint8_t q[512];   // copy of the query, for retrying on the secondary upstream
};
static Pending pending[MAX_PENDING];
static sockaddr_in upstream[2];
static portMUX_TYPE upMux = portMUX_INITIALIZER_UNLOCKED;

static void setUpstreams(const String& a, const String& b) {
  IPAddress ia, ib;
  sockaddr_in s[2] = {};
  if (ia.fromString(a)) { s[0].sin_family = AF_INET; s[0].sin_port = htons(53); s[0].sin_addr.s_addr = (uint32_t)ia; }
  if (ib.fromString(b)) { s[1].sin_family = AF_INET; s[1].sin_port = htons(53); s[1].sin_addr.s_addr = (uint32_t)ib; }
  portENTER_CRITICAL(&upMux);
  upstream[0] = s[0]; upstream[1] = s[1];
  portEXIT_CRITICAL(&upMux);
}

static bool getUpstream(int i, sockaddr_in& out) {
  portENTER_CRITICAL(&upMux);
  out = upstream[i];
  portEXIT_CRITICAL(&upMux);
  return out.sin_family == AF_INET;
}

static bool idInUse(uint16_t id) {
  for (auto& p : pending) if (p.used && p.newId == id) return true;
  return false;
}

static void dnsTask(void*) {
  int ds = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  int us = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  sockaddr_in a = {};
  a.sin_family = AF_INET;
  a.sin_port = htons(53);
  a.sin_addr.s_addr = htonl(INADDR_ANY);
  if (ds < 0 || us < 0 || bind(ds, (sockaddr*)&a, sizeof a) < 0) {
    Serial.println("[dns] socket/bind failed - rebooting");
    delay(2000);
    ESP.restart();
  }
  a.sin_port = 0;
  bind(us, (sockaddr*)&a, sizeof a);
  Serial.println("[dns] listening on UDP 53");

  static uint8_t qbuf[1500];
  static uint8_t rbuf[4096];
  static uint8_t out[600];

  for (;;) {
    fd_set rf;
    FD_ZERO(&rf);
    FD_SET(ds, &rf);
    FD_SET(us, &rf);
    timeval tv = {0, 200000};
    int r = select((ds > us ? ds : us) + 1, &rf, nullptr, nullptr, &tv);
    uint32_t now = millis();

    // ---- query from a client ----
    if (r > 0 && FD_ISSET(ds, &rf)) {
      sockaddr_in src;
      socklen_t sl = sizeof src;
      int n = recvfrom(ds, qbuf, sizeof qbuf, 0, (sockaddr*)&src, &sl);
      if (n >= (int)dns::HDR && !(qbuf[2] & 0x80)) {
        dns::Question q;
        bool parsed = dns::parseQuery(qbuf, n, q);
        uint8_t v = parsed ? classify(q.name) : (uint8_t)V_ALLOW;
        recordQuery(src.sin_addr.s_addr, parsed ? q.name : "(unparsed)", parsed ? q.qtype : 0, v);

        if (v == V_BLOCK_LIST || v == V_BLOCK_CUSTOM) {
          if (q.end + 28 <= (int)sizeof out) {
            int len = dns::buildBlocked(qbuf, q, out);
            sendto(ds, out, len, 0, (sockaddr*)&src, sl);
          }
        } else {
          sockaddr_in up;
          bool have = getUpstream(0, up) || getUpstream(1, up);
          if (!have) {
            if (parsed && q.end <= (int)sizeof out) {
              int len = dns::buildError(qbuf, q, 2, out);  // SERVFAIL
              sendto(ds, out, len, 0, (sockaddr*)&src, sl);
            }
          } else {
            // find a free slot (or recycle the oldest)
            int slot = 0;
            for (int i = 0; i < MAX_PENDING; i++) {
              if (!pending[i].used) { slot = i; break; }
              if (pending[i].t < pending[slot].t) slot = i;
            }
            Pending& p = pending[slot];
            uint16_t id;
            do { id = (uint16_t)esp_random(); } while (idInUse(id));
            p.used = true;
            p.origId = dns::rd16(qbuf);
            p.newId = id;
            p.client = src;
            p.t = now;
            p.tries = 1;
            dns::wr16(qbuf, id);
            p.qlen = n <= (int)sizeof p.q ? n : 0;
            if (p.qlen) memcpy(p.q, qbuf, n);
            sendto(us, qbuf, n, 0, (sockaddr*)&up, sizeof up);
            portENTER_CRITICAL(&statMux); stForwarded++; portEXIT_CRITICAL(&statMux);
          }
        }
      }
    }

    // ---- answer from upstream ----
    if (r > 0 && FD_ISSET(us, &rf)) {
      sockaddr_in src;
      socklen_t sl = sizeof src;
      int n = recvfrom(us, rbuf, sizeof rbuf, 0, (sockaddr*)&src, &sl);
      if (n >= (int)dns::HDR) {
        sockaddr_in u0, u1;
        bool ok0 = getUpstream(0, u0), ok1 = getUpstream(1, u1);
        bool fromUp = (ok0 && src.sin_addr.s_addr == u0.sin_addr.s_addr) ||
                      (ok1 && src.sin_addr.s_addr == u1.sin_addr.s_addr);
        uint16_t id = dns::rd16(rbuf);
        if (fromUp && src.sin_port == htons(53)) {
          for (auto& p : pending) {
            if (p.used && p.newId == id) {
              dns::wr16(rbuf, p.origId);
              sendto(ds, rbuf, n, 0, (sockaddr*)&p.client, sizeof p.client);
              p.used = false;
              portENTER_CRITICAL(&statMux);
              stLatencyMs = stLatencyMs == 0 ? (now - p.t) : stLatencyMs * 0.9f + (now - p.t) * 0.1f;
              portEXIT_CRITICAL(&statMux);
              break;
            }
          }
        }
      }
    }

    // ---- retries / timeouts ----
    for (auto& p : pending) {
      if (!p.used) continue;
      uint32_t age = now - p.t;
      sockaddr_in u1;
      if (p.tries == 1 && age > UPSTREAM_RETRY_MS && p.qlen && getUpstream(1, u1)) {
        sendto(us, p.q, p.qlen, 0, (sockaddr*)&u1, sizeof u1);
        p.tries = 2;
        p.t = now;
      } else if (age > UPSTREAM_GIVEUP_MS) {
        p.used = false;
        portENTER_CRITICAL(&statMux); stFailed++; portEXIT_CRITICAL(&statMux);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Config (NVS)
// ---------------------------------------------------------------------------
static void loadConfig() {
  prefs.begin("esphole", true);
  cfg.ssid = prefs.getString("ssid", "");
  cfg.pass = prefs.getString("pass", "");
  cfg.admin = prefs.getString("admin", "");
  cfg.host = prefs.getString("host", "esphole");
  cfg.ip = prefs.getString("ip", "");
  cfg.gw = prefs.getString("gw", "");
  cfg.mask = prefs.getString("mask", "255.255.255.0");
  cfg.up1 = prefs.getString("up1", "1.1.1.1");
  cfg.up2 = prefs.getString("up2", "9.9.9.9");
  prefs.end();
}

static void saveConfig() {
  prefs.begin("esphole", false);
  prefs.putString("ssid", cfg.ssid);
  prefs.putString("pass", cfg.pass);
  prefs.putString("admin", cfg.admin);
  prefs.putString("host", cfg.host);
  prefs.putString("ip", cfg.ip);
  prefs.putString("gw", cfg.gw);
  prefs.putString("mask", cfg.mask);
  prefs.putString("up1", cfg.up1);
  prefs.putString("up2", cfg.up2);
  prefs.end();
}

static void wipeWifi() {
  prefs.begin("esphole", false);
  prefs.remove("ssid");
  prefs.remove("pass");
  prefs.end();
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
static String ipStr(uint32_t ip) {
  uint8_t* b = (uint8_t*)&ip;
  char s[16];
  snprintf(s, sizeof s, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
  return String(s);
}

static void jsonEsc(String& out, const char* s) {
  out += '"';
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') { out += '\\'; out += (char)c; }
    else if (c < 0x20 || c > 0x7E) { char b[8]; snprintf(b, sizeof b, "\\u%04x", c); out += b; }
    else out += (char)c;
  }
  out += '"';
}

static String htmlEsc(const String& s) {
  String o;
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '<') o += "&lt;"; else if (c == '>') o += "&gt;";
    else if (c == '&') o += "&amp;"; else if (c == '"') o += "&quot;";
    else o += c;
  }
  return o;
}

static bool auth() {
  if (server.authenticate("admin", cfg.admin.c_str())) return true;
  server.requestAuthentication(BASIC_AUTH, "ESPHole32");
  return false;
}

static void sendJson(int code, const String& body) {
  server.sendHeader("Cache-Control", "no-store");
  server.send(code, "application/json", body);
}


// ---------------------------------------------------------------------------
// Wi-Fi diagnostics (printed to the Serial Monitor)
// ---------------------------------------------------------------------------
static const char* authName(int a) {
  switch (a) {
    case 0: return "OPEN"; case 1: return "WEP"; case 2: return "WPA-PSK"; case 3: return "WPA2-PSK";
    case 4: return "WPA/WPA2-PSK"; case 5: return "WPA2-ENTERPRISE (not supported)"; case 6: return "WPA3-PSK";
    case 7: return "WPA2/WPA3-PSK"; default: return "OTHER";
  }
}

static const char* reasonText(int r) {
  switch (r) {
    case 2: case 6: case 7: return "rejected by access point (may need device registration)";
    case 15: case 204: return "wrong Wi-Fi password (handshake failed)";
    case 201: return "network not found on 2.4 GHz (check name / band)";
    case 202: return "authentication failed (wrong password or unsupported security)";
    case 203: return "association failed";
    case 205: return "connection failed";
    case 8: return "left the network";
    default: return "see ESP-IDF wifi_err_reason_t";
  }
}

static int lastDiscReason = 0;

static void wifiDiag() {
  WiFi.onEvent([](WiFiEvent_t, WiFiEventInfo_t info) {
    int r = info.wifi_sta_disconnected.reason;
    if (r != lastDiscReason) Serial.printf("\n[wifi] disconnect reason %d: %s\n", r, reasonText(r));
    lastDiscReason = r;
  }, ARDUINO_EVENT_WIFI_STA_DISCONNECTED);
}

static void printScan(int n, const String& want) {
  bool found = false;
  Serial.printf("[scan] %d networks visible on 2.4 GHz:\n", n);
  for (int i = 0; i < n; i++) {
    bool match = WiFi.SSID(i) == want;
    if (match) found = true;
    Serial.printf("  %s '%s'  signal %d dBm  ch %d  %s\n", match ? "->" : "  ", WiFi.SSID(i).c_str(), WiFi.RSSI(i),
                  WiFi.channel(i), authName(WiFi.encryptionType(i)));
  }
  if (want.length() && !found)
    Serial.printf("[scan] '%s' NOT seen - name must match exactly (capitals/spaces), and it must be on 2.4 GHz\n",
                  want.c_str());
}

// ---------------------------------------------------------------------------
// Setup portal (first boot, or when Wi-Fi can't connect)
// ---------------------------------------------------------------------------
static String scannedOptions;
static uint32_t portalStarted = 0;

static void handlePortalRoot() {
  String page = FPSTR(PORTAL_HTML);
  page.replace("%NETWORKS%", scannedOptions);
  page.replace("%SSID%", htmlEsc(cfg.ssid));
  page.replace("%HOST%", htmlEsc(cfg.host));
  page.replace("%IP%", htmlEsc(cfg.ip));
  page.replace("%GW%", htmlEsc(cfg.gw));
  page.replace("%MASK%", htmlEsc(cfg.mask));
  page.replace("%ADMINHINT%", cfg.admin.length() ? "leave blank to keep current" : "at least 8 characters");
  server.send(200, "text/html", page);
}

static void handlePortalSave() {
  String ssid = server.arg("ssid"), admin = server.arg("admin"), host = server.arg("host");
  ssid.trim(); host.trim(); host.toLowerCase();
  String err;
  if (!ssid.length()) err = "Wi-Fi name is required.";
  if (admin.length() && admin.length() < 8) err = "Admin password must be at least 8 characters.";
  if (!admin.length() && !cfg.admin.length()) err = "Please set an admin password.";
  for (size_t i = 0; i < host.length(); i++)
    if (!(isalnum((unsigned char)host[i]) || host[i] == '-')) err = "Hostname: letters, numbers and - only.";
  IPAddress t;
  String ip = server.arg("ip"), gw = server.arg("gw"), mask = server.arg("mask");
  ip.trim(); gw.trim(); mask.trim();
  if (ip.length() && (!t.fromString(ip) || !t.fromString(gw) || !t.fromString(mask)))
    err = "Static IP needs a valid IP, gateway and subnet mask (or leave IP blank for DHCP).";
  if (err.length()) {
    server.send(400, "text/html", "<meta name=viewport content='width=device-width'><p>" + htmlEsc(err) +
                                      "</p><p><a href='/'>Back</a></p>");
    return;
  }
  cfg.ssid = ssid;
  cfg.pass = server.arg("pass");
  if (admin.length()) cfg.admin = admin;
  cfg.host = host.length() ? host : "esphole";
  cfg.ip = ip; cfg.gw = gw; cfg.mask = mask.length() ? mask : "255.255.255.0";
  saveConfig();
  server.send(200, "text/html",
              "<meta name=viewport content='width=device-width'><h3>Saved.</h3><p>Rebooting and joining <b>" +
                  htmlEsc(ssid) + "</b>. Then open <b>http://" + htmlEsc(cfg.host) +
                  ".local</b> or check your router for the board's IP.</p>");
  delay(1500);
  ESP.restart();
}

static void startPortal() {
  portalMode = true;
  Serial.println("[portal] starting setup hotspot");
  WiFi.disconnect(true);
  WiFi.mode(WIFI_AP_STA);
  int n = WiFi.scanNetworks();
  printScan(n, cfg.ssid);
  scannedOptions = "";
  for (int i = 0; i < n; i++) scannedOptions += "<option value=\"" + htmlEsc(WiFi.SSID(i)) + "\">";
  WiFi.softAP(SETUP_AP_SSID, SETUP_AP_PASS);
  delay(200);
  portalDns.start(53, "*", WiFi.softAPIP());
  server.on("/", HTTP_GET, handlePortalRoot);
  server.on("/save", HTTP_POST, handlePortalSave);
  server.onNotFound([]() {
    server.sendHeader("Location", "http://" + WiFi.softAPIP().toString() + "/");
    server.send(302, "text/plain", "");
  });
  server.begin();
  portalStarted = millis();
  Serial.printf("[portal] join Wi-Fi '%s' (password '%s') and open http://%s\n", SETUP_AP_SSID, SETUP_AP_PASS,
                WiFi.softAPIP().toString().c_str());
}

// ---------------------------------------------------------------------------
// Dashboard + API
// ---------------------------------------------------------------------------
static void handleStats() {
  if (!auth()) return;
  ClientStat cs[MAX_CLIENTS];
  uint32_t tot, blk, fwd, fail;
  float lat;
  portENTER_CRITICAL(&statMux);
  memcpy(cs, clients, sizeof cs);
  tot = stTotal; blk = stBlocked; fwd = stForwarded; fail = stFailed; lat = stLatencyMs;
  portEXIT_CRITICAL(&statMux);

  uint32_t now = millis();
  String j;
  j.reserve(3000);
  j += "{\"version\":\"" FW_VERSION "\"";
  j += ",\"uptime\":" + String(now / 1000);
  j += ",\"total\":" + String(tot);
  j += ",\"blocked\":" + String(blk);
  j += ",\"forwarded\":" + String(fwd);
  j += ",\"failed\":" + String(fail);
  j += ",\"latency\":" + String(lat, 1);
  j += ",\"blCount\":" + String(blCount);
  j += ",\"blCapacity\":" + String(blCapacity());
  j += ",\"paused\":" + String(isPaused() ? "true" : "false");
  j += ",\"pauseLeft\":" + String(pausedForever ? -1 : (isPaused() ? (int32_t)(pauseUntil - now) / 1000 : 0));
  j += ",\"up1\":"; jsonEsc(j, cfg.up1.c_str());
  j += ",\"up2\":"; jsonEsc(j, cfg.up2.c_str());
  j += ",\"ip\":\"" + WiFi.localIP().toString() + "\"";
  j += ",\"host\":"; jsonEsc(j, cfg.host.c_str());
  j += ",\"rssi\":" + String(WiFi.RSSI());
  j += ",\"heap\":" + String(ESP.getFreeHeap());
  j += ",\"clients\":[";
  bool first = true;
  for (auto& c : cs) {
    if (!c.ip) continue;
    if (!first) j += ',';
    first = false;
    j += "{\"ip\":\"" + ipStr(c.ip) + "\",\"q\":" + String(c.queries) + ",\"b\":" + String(c.blocked) +
         ",\"ago\":" + String((now - c.lastMs) / 1000) + "}";
  }
  j += "],\"block\":[";
  xSemaphoreTake(listMutex, portMAX_DELAY);
  for (size_t i = 0; i < blockList.size(); i++) { if (i) j += ','; jsonEsc(j, blockList[i].c_str()); }
  j += "],\"allow\":[";
  for (size_t i = 0; i < allowList.size(); i++) { if (i) j += ','; jsonEsc(j, allowList[i].c_str()); }
  xSemaphoreGive(listMutex);
  j += "]}";
  sendJson(200, j);
}

static void handleLog() {
  if (!auth()) return;
  static LogEntry copy[LOG_SIZE];
  uint16_t head, count;
  portENTER_CRITICAL(&statMux);
  memcpy(copy, logRing, sizeof copy);
  head = logHead; count = logCount;
  portEXIT_CRITICAL(&statMux);
  uint32_t now = millis();
  String j;
  j.reserve(count * 110 + 16);
  j += '[';
  for (uint16_t k = 0; k < count; k++) {
    const LogEntry& e = copy[(head + LOG_SIZE - 1 - k) % LOG_SIZE];  // newest first
    if (k) j += ',';
    j += "{\"ago\":" + String((now - e.ms) / 1000) + ",\"ip\":\"" + ipStr(e.ip) + "\",\"t\":" + String(e.qtype) +
         ",\"v\":" + String(e.verdict) + ",\"d\":";
    jsonEsc(j, e.name);
    j += '}';
  }
  j += ']';
  sendJson(200, j);
}

static void handleList() {
  if (!auth()) return;
  String list = server.arg("list"), op = server.arg("op");
  String d = cleanDomain(server.arg("domain"));
  if (d == "") { sendJson(400, "{\"error\":\"Invalid domain\"}"); return; }
  bool isBlock = list == "block";
  if (!isBlock && list != "allow") { sendJson(400, "{\"error\":\"Unknown list\"}"); return; }
  String err;
  xSemaphoreTake(listMutex, portMAX_DELAY);
  std::vector<String>& l = isBlock ? blockList : allowList;
  std::vector<String>& other = isBlock ? allowList : blockList;
  if (op == "add") {
    if (inList(l, d.c_str())) {
    } else if (l.size() >= MAX_LIST_ENTRIES) {
      err = "List is full";
    } else {
      l.push_back(d);
      for (size_t i = 0; i < other.size(); i++)  // a domain can't be on both lists
        if (other[i] == d) { other.erase(other.begin() + i); break; }
    }
  } else if (op == "remove") {
    for (size_t i = 0; i < l.size(); i++)
      if (l[i] == d) { l.erase(l.begin() + i); break; }
  } else {
    err = "Unknown op";
  }
  xSemaphoreGive(listMutex);
  if (err.length()) { sendJson(400, "{\"error\":\"" + err + "\"}"); return; }
  xSemaphoreTake(listMutex, portMAX_DELAY);
  saveList("/block.txt", blockList);
  saveList("/allow.txt", allowList);
  xSemaphoreGive(listMutex);
  sendJson(200, "{\"ok\":true}");
}

static void handlePause() {
  if (!auth()) return;
  long m = server.arg("minutes").toInt();
  if (m == 0) { pausedForever = false; pauseUntil = 0; }
  else if (m < 0) { pausedForever = true; }
  else { pausedForever = false; pauseUntil = millis() + (uint32_t)m * 60000UL; if (!pauseUntil) pauseUntil = 1; }
  sendJson(200, "{\"ok\":true}");
}

static void handleSettings() {
  if (!auth()) return;
  IPAddress a, b;
  String u1 = server.arg("up1"), u2 = server.arg("up2");
  u1.trim(); u2.trim();
  if (!a.fromString(u1) || (u2.length() && !b.fromString(u2))) {
    sendJson(400, "{\"error\":\"Upstreams must be IPv4 addresses\"}");
    return;
  }
  cfg.up1 = u1; cfg.up2 = u2;
  saveConfig();
  setUpstreams(cfg.up1, cfg.up2);
  sendJson(200, "{\"ok\":true}");
}

// --- blocklist upload: written straight into the flash partition ---
static bool upOk = false;
static String upErr;
static size_t upOff = 0, upErased = 0;

static void handleUploadData() {
  HTTPUpload& u = server.upload();
  if (u.status == UPLOAD_FILE_START) {
    upOk = server.authenticate("admin", cfg.admin.c_str()) && blPart;
    upErr = upOk ? "" : "Not authorised";
    upOff = upErased = 0;
    if (upOk) { blReady = false; blCount = 0; Serial.println("[blocklist] upload started"); }
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!upOk) return;
    if (upOff + u.currentSize > blPart->size) { upOk = false; upErr = "File is larger than the blocklist partition"; return; }
    while (upErased < upOff + u.currentSize) {
      if (esp_partition_erase_range(blPart, upErased, 4096) != ESP_OK) { upOk = false; upErr = "Flash erase failed"; return; }
      upErased += 4096;
    }
    if (esp_partition_write(blPart, upOff, u.buf, u.currentSize) != ESP_OK) { upOk = false; upErr = "Flash write failed"; return; }
    upOff += u.currentSize;
  } else if (u.status == UPLOAD_FILE_END) {
    if (!upOk) return;
    uint8_t hdr[dns::BL_HEADER];
    esp_partition_read(blPart, 0, hdr, sizeof hdr);
    long c = dns::parseHeader(hdr, blPart->size);
    if (c < 0 || dns::BL_HEADER + (size_t)c * dns::BL_ENTRY != upOff) {
      upOk = false;
      upErr = "Not a valid blocklist.bin (build it with tools/build_blocklist.py)";
      return;
    }
    // spot-check ordering of the first entries
    uint8_t p[5], q[5];
    for (uint32_t i = 1; i < (uint32_t)c && i < 2000; i++) {
      blReadEntry(i - 1, p); blReadEntry(i, q);
      if (dns::decode40(p) >= dns::decode40(q)) { upOk = false; upErr = "Blocklist is not sorted"; return; }
    }
    loadBlocklist();
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    upOk = false;
    upErr = "Upload aborted";
  }
}

static void handleUploadDone() {
  if (!auth()) return;
  if (upOk) sendJson(200, "{\"ok\":true,\"count\":" + String(blCount) + "}");
  else {
    String j = "{\"error\":";
    jsonEsc(j, upErr.c_str());
    j += "}";
    sendJson(400, j);
  }
}

static void startDashboard() {
  server.on("/", HTTP_GET, []() {
    if (!auth()) return;
    server.sendHeader("Cache-Control", "no-store");
    server.send_P(200, "text/html", DASHBOARD_HTML);
  });
  server.on("/api/stats", HTTP_GET, handleStats);
  server.on("/api/log", HTTP_GET, handleLog);
  server.on("/api/list", HTTP_POST, handleList);
  server.on("/api/pause", HTTP_POST, handlePause);
  server.on("/api/settings", HTTP_POST, handleSettings);
  server.on("/api/blocklist", HTTP_POST, handleUploadDone, handleUploadData);
  server.on("/api/reboot", HTTP_POST, []() {
    if (!auth()) return;
    sendJson(200, "{\"ok\":true}");
    delay(500);
    ESP.restart();
  });
  server.on("/api/wifireset", HTTP_POST, []() {
    if (!auth()) return;
    sendJson(200, "{\"ok\":true}");
    wipeWifi();
    delay(500);
    ESP.restart();
  });
  server.onNotFound([]() { server.send(404, "text/plain", "Not found"); });
  server.begin();
}

// ---------------------------------------------------------------------------
// Wi-Fi
// ---------------------------------------------------------------------------
static bool connectWifi() {
  WiFi.mode(WIFI_STA);
  wifiDiag();
  int n = WiFi.scanNetworks();
  printScan(n, cfg.ssid);
  // Pick the strongest access point broadcasting our network name
  int best = -1;
  for (int i = 0; i < n; i++)
    if (WiFi.SSID(i) == cfg.ssid && (best < 0 || WiFi.RSSI(i) > WiFi.RSSI(best))) best = i;
  uint8_t bestBssid[6];
  int32_t bestChannel = 0;
  if (best >= 0) {
    memcpy(bestBssid, WiFi.BSSID(best), 6);
    bestChannel = WiFi.channel(best);
    Serial.printf("[wifi] strongest access point: %s ch %d (%d dBm)\n", WiFi.BSSIDstr(best).c_str(),
                  (int)bestChannel, (int)WiFi.RSSI(best));
  }
  WiFi.setHostname(cfg.host.c_str());
  if (cfg.ip.length()) {
    IPAddress ip, gw, mask;
    ip.fromString(cfg.ip); gw.fromString(cfg.gw); mask.fromString(cfg.mask);
    WiFi.config(ip, gw, mask, IPAddress(1, 1, 1, 1), IPAddress(9, 9, 9, 9));
  }
  WiFi.setAutoReconnect(true);
  if (best >= 0) WiFi.begin(cfg.ssid.c_str(), cfg.pass.c_str(), bestChannel, bestBssid);
  else WiFi.begin(cfg.ssid.c_str(), cfg.pass.c_str());
  Serial.printf("[wifi] connecting to '%s'", cfg.ssid.c_str());
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 25000) { delay(500); Serial.print('.'); }
  Serial.println();
  if (WiFi.status() != WL_CONNECTED) return false;
  WiFi.setSleep(false);  // keeps DNS replies fast
  Serial.printf("[wifi] connected, IP %s\n", WiFi.localIP().toString().c_str());
  return true;
}

// ---------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("\n=== ESPHole32 v" FW_VERSION " ===");
  pinMode(BOOT_BUTTON_PIN, INPUT_PULLUP);

  listMutex = xSemaphoreCreateMutex();
  if (!LittleFS.begin(true)) Serial.println("[fs] LittleFS mount failed");
  loadList("/block.txt", blockList);
  loadList("/allow.txt", allowList);

  blPart = esp_partition_find_first((esp_partition_type_t)0x01, (esp_partition_subtype_t)0x40, "blocklist");
  if (!blPart) Serial.println("[blocklist] partition missing - check partitions.csv");
  loadBlocklist();

  loadConfig();
  setUpstreams(cfg.up1, cfg.up2);

  if (!cfg.ssid.length() || !cfg.admin.length() || !connectWifi()) {
    startPortal();
    return;
  }

  if (MDNS.begin(cfg.host.c_str())) MDNS.addService("http", "tcp", 80);
  startDashboard();
  xTaskCreatePinnedToCore(dnsTask, "dns", 8192, nullptr, 3, nullptr, 0);
  Serial.printf("[ready] dashboard: http://%s/  or  http://%s.local/\n", WiFi.localIP().toString().c_str(),
                cfg.host.c_str());
  Serial.printf("[ready] set your router's DNS server to %s\n", WiFi.localIP().toString().c_str());
}

void loop() {
  static uint32_t btnDown = 0, lostSince = 0, highSince = 0;
  static bool armed = false;

  // Hold BOOT for 10 s -> forget Wi-Fi and reboot into the setup portal.
  // Only armed once the button has read "released" for 3 s after start-up, so a
  // USB/serial adapter holding GPIO0 low can't wipe the settings by accident.
  bool pressed = digitalRead(BOOT_BUTTON_PIN) == LOW;
  if (!armed) {
    if (pressed) highSince = 0;
    else if (!highSince) highSince = millis();
    else if (millis() - highSince > 3000) armed = true;
  } else if (pressed) {
    if (!btnDown) { btnDown = millis(); Serial.println("[reset] BOOT pressed - keep holding 10 s to forget Wi-Fi"); }
    if (millis() - btnDown > 10000) {
      Serial.println("[reset] Wi-Fi settings cleared");
      wipeWifi();
      delay(300);
      ESP.restart();
    }
  } else {
    if (btnDown) Serial.println("[reset] BOOT released - nothing changed");
    btnDown = 0;
  }

  if (portalMode) {
    portalDns.processNextRequest();
    server.handleClient();
    // If we already have saved Wi-Fi (e.g. the router was just slow to boot after a
    // power cut), don't sit in the portal forever - retry every 3 minutes.
    if (cfg.ssid.length() && cfg.admin.length() && millis() - portalStarted > 180000 && WiFi.softAPgetStationNum() == 0)
      ESP.restart();
    delay(2);
    return;
  }

  server.handleClient();

  // Reboot if Wi-Fi has been gone for 5 minutes
  if (WiFi.status() != WL_CONNECTED) {
    if (!lostSince) lostSince = millis();
    if (millis() - lostSince > 300000) ESP.restart();
  } else {
    lostSince = 0;
  }
  delay(2);
}