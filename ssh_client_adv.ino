/*
 * SSH Client  –  M5Cardputer / M5Cardputer-Adv
 * ─────────────────────────────────────────────
 * Libraries (Arduino IDE):
 *   Board manager  >= 3.2.6   (ESP-IDF 5.4)
 *   M5Cardputer   >= 1.1.1  |  M5Unified >= 0.2.8  |  M5GFX >= 0.2.10
 *   WireGuard-ESP32-bis  (ZIP from issue #45 of WireGuard-ESP32-Arduino)
 *   LibSSH-ESP32         (ZIP install from github.com/ewpa/LibSSH-ESP32)
 *
 * SD layout:
 *   /SSHAdv/wifi.cfg      – saved WiFi credentials
 *   /SSHAdv/users.cfg     – remembered SSH usernames
 *   /SSHAdv/settings.cfg  – all settings
 *   /SSHAdv/<n>.prof      – SSH profiles
 *   /SSHAdv/wg/<x>.conf   – WireGuard configs
 *
 * Navigation (menus):
 *   ;  = Up   .  = Down   ,  = Back   /  = Forward   Enter = Select
 *
 * SSH terminal:
 *   All keys type normally — ; . , / are literal characters
 *   Fn + ; . , /  →  Up / Down / Left / Right arrow
 *   Fn + Q        →  Quit session
 *   Fn + F        →  Toggle font size
 *   Ctrl + letter →  Send control character (^C, ^D, ^Z …)
 *   G0 button     →  Quit session
 */

#include <WiFi.h>
#include <M5Cardputer.h>
#include <WireGuard-ESP32.h>
#include <SD.h>
#include <FS.h>
#include <math.h>
#include "libssh_esp32.h"
#include <libssh/libssh.h>
#include "lwip/sockets.h"

// ── Display ────────────────────────────────────────────────────────────────────
#define DW       240
#define DH       135
#define TITLEH   20
#define HINTH    12
#define BODYY    (TITLEH + 2)
#define BODYH    (DH - TITLEH - HINTH - 4)
#define LH       18
#define LHS      10

// ── Colours ───────────────────────────────────────────────────────────────────
#define C_BG     TFT_BLACK
#define C_FG     TFT_WHITE
#define C_DIM    0x4228u
#define C_SELBG  0x0338u
#define C_SELFG  TFT_WHITE
#define C_TITBG  0x000Bu
#define C_TITFG  0x07FFu
#define C_HNTBG  0x1082u
#define C_HNTFG  0x7BCFu
#define C_OK     0x07E0u
#define C_ERR    TFT_RED
#define C_WARN   TFT_YELLOW
#define C_WIFI   0x07FFu
#define C_PROF   0xFD20u
#define C_SETT   0x632Cu

// ── Limits ─────────────────────────────────────────────────────────────────────
#define MAX_PROF  20
#define MAX_NET   20
#define MAX_WGF   20
#define MAX_USR   12

// ── Nav key codes ──────────────────────────────────────────────────────────────
#define KUP    ';'
#define KDOWN  '.'
#define KLEFT  ','
#define KRIGHT '/'

// ── Type forward declarations (required for Arduino 3.x preprocessor) ──────────
struct Profile;
struct LItem;
struct Settings;

// ── Profile ────────────────────────────────────────────────────────────────────
struct Profile {
    char name[32];
    char host[64];
    char user[32];
    char pass[64];
    int  port;
    bool useWG;
    char wg_conffile[40];
    char wg_privkey[50];
    char wg_addr[24];
    char wg_pubkey[50];
    char wg_endpoint[48];
};

struct LItem {
    char     label[44];
    char     sub[28];
    uint16_t lc;
    uint16_t dot;
};

// ── Settings ──────────────────────────────────────────────────────────────────
struct Settings {
    int  screenTimeoutSec;
    int  sshTimeoutMin;
    int  wifiTimeoutMin;
    int  brightness;
    int  termFontSize;
    bool keepAlive;
    bool buzzer;
    int  defaultPort;
    bool autoConnect;
    int  passDisplay;   // 0=hide all, 1=show last 3, 2=show all
};

// ── Globals ────────────────────────────────────────────────────────────────────
Profile  g_prof[MAX_PROF];
int      g_profCnt  = 0;
int      g_profSel  = 0;

static WireGuard* g_wg = nullptr;
static char g_wgFingerprint[128] = "";
static bool g_wgTcpUsed = false;       // set once SSH connects through WG; end() unsafe after

#include "lwip/netif.h"
#include "lwip/tcpip.h"

RTC_DATA_ATTR static int  g_bootProfileIdx = -1;   // profile to auto-connect after WG restart
static struct netif* g_prevDefaultNetif = nullptr;  // WiFi netif (saved before WG begin)
static struct netif* g_wgNetif          = nullptr;  // WG netif  (saved after  WG begin)

void wgFingerprint(const Profile& p, char* out, int sz) {
    snprintf(out, sz, "%s|%s", p.wg_endpoint, p.wg_pubkey);
}

// Restore WiFi as default route, leave WG netif registered but inactive.
void wgSuspend() {
    if (g_prevDefaultNetif) {
        LOCK_TCPIP_CORE();
        netif_set_default(g_prevDefaultNetif);
        UNLOCK_TCPIP_CORE();
    }
}

// Re-enable WG as default route (same-config reuse).
void wgResume() {
    if (g_wgNetif) {
        LOCK_TCPIP_CORE();
        netif_set_default(g_wgNetif);
        UNLOCK_TCPIP_CORE();
    }
}

char     g_ssid[64]  = "";
char     g_wpass[64] = "";
bool     g_wifiOk    = false;

char     g_users[MAX_USR][32];
int      g_userCnt   = 0;

Settings g_cfg = { 60, 0, 0, 128, 1, true, false, 22, true, 0 };

struct SSHTaskCtx {
    Profile      prof;
    ssh_session  sess;
    ssh_channel  ch;
    volatile int state;   // 0=running, 1=ok, 2=failed
    char         errmsg[80];
};
static SSHTaskCtx    g_sshCtx;
static volatile bool g_taskAbort = false;
static TaskHandle_t  g_sshTask   = nullptr;

unsigned long g_lastKey       = 0;
unsigned long g_lastAct       = 0;
unsigned long g_lastWifiRetry = 0;
bool     g_dimmed    = false;
#define DEBOUNCE_MS 130

const char* P_WIFI  = "/SSHAdv/wifi.cfg";
const char* P_USERS = "/SSHAdv/users.cfg";
const char* P_SETT  = "/SSHAdv/settings.cfg";
const char* P_WG    = "/SSHAdv/wg";

// ── Forward declarations ───────────────────────────────────────────────────────
void runHome();
void runWifiMenu();
void runProfileList();
void runConnect(int idx);
void runSSHTerm(ssh_session sess, ssh_channel ch);
void editProfile(int idx);
void runSettings();
void touchActivity();
void drawWifiIcon(int cx, int cy, uint16_t col);
void drawSshIcon(int cx, int cy, uint16_t col, uint16_t bg);
void drawGearIcon(int cx, int cy, uint16_t col);


// ═══════════════════════════════════════════════════════════════════════════════
//  SCREEN TIMEOUT
// ═══════════════════════════════════════════════════════════════════════════════

void touchActivity() {
    g_lastAct = millis();
    if (g_dimmed) {
        M5Cardputer.Display.setBrightness(128);
        g_dimmed = false;
    }
}

void checkScreenTimeout() {
    if (g_cfg.screenTimeoutSec <= 0 || g_dimmed) return;
    if ((millis() - g_lastAct) > (unsigned long)g_cfg.screenTimeoutSec * 1000UL) {
        M5Cardputer.Display.setBrightness(0);
        g_dimmed = true;
    }
}

void checkWifiRetry() {
    // Detect silent WiFi drops
    if (g_wifiOk && WiFi.status() != WL_CONNECTED) g_wifiOk = false;
    if (g_cfg.wifiTimeoutMin <= 0) return;
    if (g_wifiOk) return;
    if (!g_ssid[0]) return;
    unsigned long interval = (unsigned long)g_cfg.wifiTimeoutMin * 60000UL;
    if ((millis() - g_lastWifiRetry) < interval) return;
    g_lastWifiRetry = millis();
    WiFi.begin(g_ssid, g_wpass);
    for (int i = 0; i < 10 && WiFi.status() != WL_CONNECTED; i++)
        vTaskDelay(300 / portTICK_PERIOD_MS);
    g_wifiOk = (WiFi.status() == WL_CONNECTED);
}


// ═══════════════════════════════════════════════════════════════════════════════
//  INPUT HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

inline bool isFn()   { return M5Cardputer.Keyboard.isKeyPressed(KEY_FN); }
inline bool isCtrl() { return M5Cardputer.Keyboard.isKeyPressed(KEY_LEFT_CTRL); }

inline char hidToAlpha(uint8_t hid) {
    if (hid >= 0x04 && hid <= 0x1D) return 'a' + (hid - 0x04);
    return 0;
}

Keyboard_Class::KeysState waitKS() {
    while (true) {
        vTaskDelay(20 / portTICK_PERIOD_MS);
        checkScreenTimeout();
        checkWifiRetry();
        M5Cardputer.update();
        if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
            touchActivity();
            if (g_cfg.buzzer) M5Cardputer.Speaker.tone(4000, 20);
            return M5Cardputer.Keyboard.keysState();
        }
    }
}

char waitCh() {
    while (true) {
        auto st = waitKS();
        if (st.enter) return '\r';
        if (st.del)   return '\b';
        for (auto c : st.word) {
            if ((uint8_t)c == 0x1b) return KLEFT;
            return c;
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  DISPLAY PRIMITIVES
// ═══════════════════════════════════════════════════════════════════════════════

void titleBar(const char* t) {
    M5Cardputer.Display.fillRect(0, 0, DW, TITLEH, C_TITBG);
    M5Cardputer.Display.setTextSize(2);
    M5Cardputer.Display.setTextColor(C_TITFG, C_TITBG);
    M5Cardputer.Display.setCursor(4, 2);
    M5Cardputer.Display.print(t);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextColor(g_wifiOk ? C_OK : C_DIM, C_TITBG);
    M5Cardputer.Display.setCursor(DW - 24, 6);
    M5Cardputer.Display.print(g_wifiOk ? "WiFi" : "----");
}

void hintBar(const char* h) {
    int y = DH - HINTH;
    M5Cardputer.Display.fillRect(0, y, DW, HINTH, C_HNTBG);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextColor(C_HNTFG, C_HNTBG);
    M5Cardputer.Display.setCursor(3, y + 1);
    M5Cardputer.Display.print(h);
}

void screenInit(const char* t, const char* h) {
    M5Cardputer.Display.fillScreen(C_BG);
    titleBar(t);
    hintBar(h);
    M5Cardputer.Display.setTextSize(2);
    M5Cardputer.Display.setTextColor(C_FG, C_BG);
    M5Cardputer.Display.setCursor(0, BODYY);
}

void bprint(const char* s, uint16_t col = C_FG) {
    int lim = DH - HINTH - LH;
    if (M5Cardputer.Display.getCursorY() > lim) {
        M5Cardputer.Display.scroll(0, -LH);
        M5Cardputer.Display.fillRect(0, lim, DW, LH, C_BG);
        M5Cardputer.Display.setCursor(0, lim);
    }
    M5Cardputer.Display.setTextSize(2);
    M5Cardputer.Display.setTextColor(col, C_BG);
    M5Cardputer.Display.println(s);
}

void bprintf(uint16_t col, const char* fmt, ...) {
    char buf[128]; va_list a; va_start(a, fmt);
    vsnprintf(buf, sizeof(buf), fmt, a); va_end(a);
    bprint(buf, col);
}

// Start a fresh WireGuard tunnel. Defined after bprint() for default-arg safety.
bool wgStart(const Profile& p, const char* fp) {
    IPAddress tun;
    String a = p.wg_addr; int sl = a.indexOf('/'); if (sl >= 0) a = a.substring(0, sl);
    if (!tun.fromString(a)) { bprint("Bad WG IP!", C_ERR); delay(2000); return false; }
    String ep = p.wg_endpoint;
    int co = ep.lastIndexOf(':');
    if (co < 0) { bprint("Bad WG endpoint!", C_ERR); delay(2000); return false; }
    configTime(0, 0, "pool.ntp.org", "time.google.com"); delay(800);
    g_prevDefaultNetif = netif_default;
    g_wg = new WireGuard();
    g_wg->begin(tun, p.wg_privkey, ep.substring(0, co).c_str(),
               p.wg_pubkey, ep.substring(co + 1).toInt());
    g_wgNetif   = netif_default;
    g_wgTcpUsed = false;
    strncpy(g_wgFingerprint, fp, sizeof(g_wgFingerprint)-1);
    bprint("WG up.", C_OK);
    return true;
}


// ═══════════════════════════════════════════════════════════════════════════════
//  GENERIC SCROLLABLE LIST  with marquee on selected row
// ═══════════════════════════════════════════════════════════════════════════════

int visRows() { return BODYH / LH; }

static int labelCols(bool hasSub) { return hasSub ? 14 : 18; }

void drawRow(const LItem& it, int y, bool hi, int marqOff) {
    uint16_t bg = hi ? C_SELBG : C_BG;
    if (hi) M5Cardputer.Display.fillRect(0, y, DW, LH, C_SELBG);
    if (it.dot)
        M5Cardputer.Display.fillCircle(5, y + LH/2, 3, it.dot);

    int maxCols = labelCols(it.sub[0] != '\0');
    int lblLen  = strlen(it.label);

    char lbuf[20];
    if (!hi || lblLen <= maxCols) {
        strncpy(lbuf, it.label, maxCols);
        lbuf[maxCols] = '\0';
    } else {
        int off = marqOff % (lblLen + 3);
        for (int i = 0; i < maxCols; i++) {
            int ci = (off + i) % (lblLen + 3);
            lbuf[i] = (ci < lblLen) ? it.label[ci] : ' ';
        }
        lbuf[maxCols] = '\0';
    }

    M5Cardputer.Display.setTextSize(2);
    M5Cardputer.Display.setTextColor(hi ? C_SELFG : it.lc, bg);
    M5Cardputer.Display.setCursor(13, y + 1);
    M5Cardputer.Display.print(lbuf);

    if (it.sub[0]) {
        int sw = strlen(it.sub) * 6;
        M5Cardputer.Display.setTextSize(1);
        M5Cardputer.Display.setTextColor(C_DIM, bg);
        M5Cardputer.Display.setCursor(DW - sw - 3, y + 5);
        M5Cardputer.Display.print(it.sub);
    }
}

void drawList(const LItem* it, int cnt, int sel, int sc,
              const char* title, const char* hint, int marqOff = 0) {
    M5Cardputer.Display.fillScreen(C_BG);
    titleBar(title);
    hintBar(hint);
    if (cnt == 0) {
        M5Cardputer.Display.setTextSize(2);
        M5Cardputer.Display.setTextColor(C_DIM, C_BG);
        M5Cardputer.Display.setCursor(6, BODYY + 6);
        M5Cardputer.Display.print("(empty)");
        return;
    }
    int rows = visRows();
    for (int i = 0; i < rows && (i + sc) < cnt; i++) {
        int idx = i + sc;
        drawRow(it[idx], BODYY + i * LH, idx == sel, (idx == sel) ? marqOff : 0);
    }
}

void redrawSelRow(const LItem* it, int cnt, int sel, int sc,
                  const char* title, const char* hint, int marqOff) {
    int rows = visRows();
    int rowIdx = sel - sc;
    if (rowIdx < 0 || rowIdx >= rows) return;
    int lblLen = strlen(it[sel].label);
    int maxCols = labelCols(it[sel].sub[0] != '\0');
    if (lblLen <= maxCols) return;
    drawRow(it[sel], BODYY + rowIdx * LH, true, marqOff);
}

int runList(LItem* it, int cnt, const char* title, const char* hint,
            int startSel = 0) {
    int rows   = visRows();
    int sel    = (startSel < cnt) ? startSel : 0;
    int sc     = (sel >= rows) ? sel - rows + 1 : 0;
    int marqOff = 0;
    unsigned long lastMarq = millis();
    const unsigned long MARQ_MS = 220;

    drawList(it, cnt, sel, sc, title, hint, marqOff);

    while (true) {
        vTaskDelay(20 / portTICK_PERIOD_MS);
        checkScreenTimeout();
        M5Cardputer.update();

        bool keyPressed = M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed();
        if (keyPressed) {
            touchActivity();
            auto st = M5Cardputer.Keyboard.keysState();
            char c = '\0';
            if (st.enter) c = '\r';
            else if (st.del) c = '\b';
            else {
                for (auto ch : st.word) {
                    if ((uint8_t)ch == 0x1b) { c = KLEFT; break; }
                    c = ch; break;
                }
            }

            if (c == KUP) {
                if (sel > 0) {
                    sel--; marqOff = 0; lastMarq = millis();
                    if (sel < sc) sc = sel;
                    drawList(it, cnt, sel, sc, title, hint, 0);
                }
            } else if (c == KDOWN) {
                if (sel < cnt-1) {
                    sel++; marqOff = 0; lastMarq = millis();
                    if (sel >= sc+rows) sc = sel-rows+1;
                    drawList(it, cnt, sel, sc, title, hint, 0);
                }
            } else if (c == '\r' || c == KRIGHT) {
                return cnt > 0 ? sel : -1;
            } else if (c == KLEFT) {
                return -1;
            }
        }

        if (millis() - lastMarq >= MARQ_MS) {
            lastMarq = millis();
            int lblLen  = strlen(it[sel].label);
            int maxCols = labelCols(it[sel].sub[0] != '\0');
            if (lblLen > maxCols) {
                marqOff++;
                redrawSelRow(it, cnt, sel, sc, title, hint, marqOff);
            }
        }
    }
}

int pickStr(const char** opts, int n, const char* title, int startSel = 0) {
    LItem items[32];
    int lim = (n < 32) ? n : 32;
    for (int i = 0; i < lim; i++) {
        strncpy(items[i].label, opts[i], sizeof(items[i].label)-1);
        items[i].label[sizeof(items[i].label)-1] = '\0';
        items[i].sub[0] = '\0';
        items[i].lc  = C_FG;
        items[i].dot = 0;
    }
    return runList(items, lim, title, "^ v = move   Enter = pick   < back", startSel);
}


// ═══════════════════════════════════════════════════════════════════════════════
//  YES / NO DIALOG
// ═══════════════════════════════════════════════════════════════════════════════

bool yesNo(const char* title, const char* q, bool defYes = false) {
    int sel = defYes ? 0 : 1;
    auto draw = [&]() {
        screenInit(title, " ,/=toggle  Enter=confirm  ,=cancel");
        M5Cardputer.Display.setTextSize(2);
        M5Cardputer.Display.setTextColor(C_WARN, C_BG);
        M5Cardputer.Display.setCursor(4, BODYY + 2);
        M5Cardputer.Display.print(q);
        int by = BODYY + LH + 12;
        uint16_t yb = (sel==0) ? C_OK  : C_DIM;
        uint16_t nb = (sel==1) ? C_ERR : C_DIM;
        M5Cardputer.Display.fillRoundRect(18,  by, 84, LH+4, 4, yb);
        M5Cardputer.Display.fillRoundRect(136, by, 84, LH+4, 4, nb);
        M5Cardputer.Display.setTextColor(C_FG, yb);
        M5Cardputer.Display.setCursor(44,  by+2); M5Cardputer.Display.print("YES");
        M5Cardputer.Display.setTextColor(C_FG, nb);
        M5Cardputer.Display.setCursor(164, by+2); M5Cardputer.Display.print("NO");
    };
    draw();
    while (true) {
        char c = waitCh();
        if (c==KLEFT||c==KUP||c==KRIGHT||c==KDOWN) { sel=1-sel; draw(); }
        if (c=='\r') return sel==0;
        if (c==KLEFT) return false;
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  TEXT INPUT
// ═══════════════════════════════════════════════════════════════════════════════

String typeText(const char* title, const char* prompt,
                const char* prefill = "", bool hidden = false) {
    screenInit(title, "Enter=done  Bksp=del  ,=cancel");
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextColor(C_DIM, C_BG);
    M5Cardputer.Display.setCursor(4, BODYY + 2);
    M5Cardputer.Display.print(prompt);

    String val = String(prefill);
    int iy = BODYY + LHS + 4;

    auto redraw = [&]() {
        M5Cardputer.Display.fillRect(0, iy, DW, LH + 4, C_BG);
        M5Cardputer.Display.setTextSize(2);
        M5Cardputer.Display.setTextColor(C_FG, C_BG);
        M5Cardputer.Display.setCursor(4, iy);
        if (hidden) {
            int len = val.length();
            if (g_cfg.passDisplay == 2) {
                M5Cardputer.Display.print(val);
            } else if (g_cfg.passDisplay == 1) {
                int show = (len >= 3) ? 3 : len;
                int hide = len - show;
                for (int i = 0; i < hide; i++) M5Cardputer.Display.print('*');
                for (int i = hide; i < len; i++) M5Cardputer.Display.print(val[i]);
            } else {
                for (int i = 0; i < len; i++) M5Cardputer.Display.print('*');
            }
        } else {
            M5Cardputer.Display.print(val);
        }
        M5Cardputer.Display.fillRect(M5Cardputer.Display.getCursorX(), iy, 8, LH, C_TITFG);
    };
    redraw();

    while (true) {
        vTaskDelay(10 / portTICK_PERIOD_MS);
        checkScreenTimeout();
        M5Cardputer.update();
        if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed()) continue;
        touchActivity();
        auto st = M5Cardputer.Keyboard.keysState();

        if (st.enter) return val;
        if (st.del && val.length()) { val.remove(val.length()-1); redraw(); continue; }
        if (M5Cardputer.Keyboard.isKeyPressed(KEY_FN)) continue;

        for (auto ch : st.word) {
            if ((uint8_t)ch == 0x1b || ch == KLEFT) return val;
            val += ch;
        }
        redraw();
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SETTINGS  LOAD / SAVE
// ═══════════════════════════════════════════════════════════════════════════════

void loadSettings() {
    File f = SD.open(P_SETT); if (!f) return;
    while (f.available()) {
        String ln = f.readStringUntil('\n'); ln.trim();
        if (!ln.length() || ln[0]=='#') continue;
        int eq = ln.indexOf('='); if (eq<0) continue;
        String k = ln.substring(0,eq); k.trim();
        String vs = ln.substring(eq+1); vs.trim();
        int    v  = vs.toInt();
        if      (k=="screen_timeout") g_cfg.screenTimeoutSec = v;
        else if (k=="ssh_timeout")    g_cfg.sshTimeoutMin    = v;
        else if (k=="wifi_timeout")   g_cfg.wifiTimeoutMin   = v;
        else if (k=="brightness")     g_cfg.brightness       = v;
        else if (k=="term_font")      g_cfg.termFontSize     = (v==2)?2:1;
        else if (k=="keepalive")      g_cfg.keepAlive        = (v==1);
        else if (k=="buzzer")         g_cfg.buzzer           = (v==1);
        else if (k=="default_port")   g_cfg.defaultPort      = v>0?v:22;
        else if (k=="auto_connect")   g_cfg.autoConnect      = (v==1);
        else if (k=="pass_display")   g_cfg.passDisplay      = (v>=0&&v<=2)?v:0;
    }
    f.close();
    M5Cardputer.Display.setBrightness(g_cfg.brightness);
}

void saveSettings() {
    SD.remove(P_SETT);
    File f = SD.open(P_SETT, FILE_WRITE); if (!f) return;
    f.printf("screen_timeout=%d\nssh_timeout=%d\nwifi_timeout=%d\n",
             g_cfg.screenTimeoutSec, g_cfg.sshTimeoutMin, g_cfg.wifiTimeoutMin);
    f.printf("brightness=%d\nterm_font=%d\nkeepalive=%d\nbuzzer=%d\ndefault_port=%d\nauto_connect=%d\npass_display=%d\n",
             g_cfg.brightness, g_cfg.termFontSize, g_cfg.keepAlive?1:0,
             g_cfg.buzzer?1:0, g_cfg.defaultPort, g_cfg.autoConnect?1:0,
             g_cfg.passDisplay);
    f.close();
}


// ═══════════════════════════════════════════════════════════════════════════════
//  FILE I/O  (profiles, wifi, users)
// ═══════════════════════════════════════════════════════════════════════════════

String profPath(const char* n) { return String("/SSHAdv/") + n + ".prof"; }

bool parseProf(File& f, Profile& p) {
    memset(&p, 0, sizeof(p)); p.port = 22;
    while (f.available()) {
        String ln = f.readStringUntil('\n'); ln.trim();
        if (!ln.length() || ln[0]=='#') continue;
        int eq = ln.indexOf('='); if (eq<0) continue;
        String k = ln.substring(0,eq); k.trim();
        String v = ln.substring(eq+1); v.trim();
        if      (k=="name")        strncpy(p.name,        v.c_str(), sizeof(p.name)-1);
        else if (k=="host")        strncpy(p.host,        v.c_str(), sizeof(p.host)-1);
        else if (k=="user")        strncpy(p.user,        v.c_str(), sizeof(p.user)-1);
        else if (k=="pass")        strncpy(p.pass,        v.c_str(), sizeof(p.pass)-1);
        else if (k=="port")        p.port = v.toInt();
        else if (k=="wg")          p.useWG = (v=="1");
        else if (k=="wg_conffile") strncpy(p.wg_conffile, v.c_str(), sizeof(p.wg_conffile)-1);
        else if (k=="wg_privkey")  strncpy(p.wg_privkey,  v.c_str(), sizeof(p.wg_privkey)-1);
        else if (k=="wg_addr")     strncpy(p.wg_addr,     v.c_str(), sizeof(p.wg_addr)-1);
        else if (k=="wg_pubkey")   strncpy(p.wg_pubkey,   v.c_str(), sizeof(p.wg_pubkey)-1);
        else if (k=="wg_endpoint") strncpy(p.wg_endpoint, v.c_str(), sizeof(p.wg_endpoint)-1);
    }
    return p.name[0] && p.host[0];
}

void loadProfiles() {
    g_profCnt = 0;
    File dir = SD.open("/SSHAdv");
    if (!dir || !dir.isDirectory()) return;
    File e;
    while ((e = dir.openNextFile()) && g_profCnt < MAX_PROF) {
        String fn = e.name();
        if (fn.endsWith(".prof")) { Profile p; if (parseProf(e,p)) g_prof[g_profCnt++] = p; }
        e.close();
    }
    dir.close();
}

void saveProf(const Profile& p) {
    SD.remove(profPath(p.name).c_str());
    File f = SD.open(profPath(p.name).c_str(), FILE_WRITE); if (!f) return;
    f.printf("name=%s\nhost=%s\nuser=%s\npass=%s\nport=%d\n",
             p.name, p.host, p.user, p.pass, p.port);
    f.printf("wg=%d\nwg_conffile=%s\nwg_privkey=%s\nwg_addr=%s\nwg_pubkey=%s\nwg_endpoint=%s\n",
             p.useWG?1:0, p.wg_conffile, p.wg_privkey, p.wg_addr, p.wg_pubkey, p.wg_endpoint);
    f.close();
}

void deleteProf(int idx) {
    SD.remove(profPath(g_prof[idx].name).c_str());
    for (int i=idx; i<g_profCnt-1; i++) g_prof[i]=g_prof[i+1];
    g_profCnt--;
    if (g_profSel >= g_profCnt && g_profSel > 0) g_profSel--;
}

void saveWifi() {
    SD.remove(P_WIFI);
    File f = SD.open(P_WIFI, FILE_WRITE); if (!f) return;
    f.println(g_ssid); f.print(g_wpass); f.close();
}

bool loadWifi() {
    File f = SD.open(P_WIFI); if (!f) return false;
    String s = f.readStringUntil('\n'); s.trim();
    String p = f.readStringUntil('\n'); p.trim();
    f.close(); if (!s.length()) return false;
    strncpy(g_ssid,  s.c_str(), sizeof(g_ssid)-1);
    strncpy(g_wpass, p.c_str(), sizeof(g_wpass)-1);
    return true;
}

void loadUsers() {
    g_userCnt = 0;
    File f = SD.open(P_USERS); if (!f) return;
    while (f.available() && g_userCnt < MAX_USR) {
        String ln = f.readStringUntil('\n'); ln.trim();
        if (ln.length()) strncpy(g_users[g_userCnt++], ln.c_str(), 31);
    }
    f.close();
}

void addUser(const char* u) {
    for (int i=0; i<g_userCnt; i++) if (strcmp(g_users[i],u)==0) return;
    File f = SD.open(P_USERS, FILE_APPEND); if (!f) return;
    f.println(u); f.close();
    if (g_userCnt < MAX_USR) strncpy(g_users[g_userCnt++], u, 31);
}


// ═══════════════════════════════════════════════════════════════════════════════
//  WIREGUARD CONFIG PICKER
// ═══════════════════════════════════════════════════════════════════════════════

bool parseWGFile(const char* path, Profile& p) {
    File f = SD.open(path); if (!f) return false;
    while (f.available()) {
        String ln = f.readStringUntil('\n'); ln.trim();
        if (!ln.length() || ln[0]=='[' || ln[0]=='#') continue;
        int eq = ln.indexOf('='); if (eq<0) continue;
        String k = ln.substring(0,eq); k.trim();
        String v = ln.substring(eq+1); v.trim();
        if      (k=="PrivateKey") strncpy(p.wg_privkey,  v.c_str(), sizeof(p.wg_privkey)-1);
        else if (k=="Address")    strncpy(p.wg_addr,     v.c_str(), sizeof(p.wg_addr)-1);
        else if (k=="PublicKey")  strncpy(p.wg_pubkey,   v.c_str(), sizeof(p.wg_pubkey)-1);
        else if (k=="Endpoint")   strncpy(p.wg_endpoint, v.c_str(), sizeof(p.wg_endpoint)-1);
    }
    f.close();
    return p.wg_privkey[0] && p.wg_endpoint[0];
}

bool pickWGConf(Profile& p) {
    static char names[MAX_WGF][40];
    static const char* ptrs[MAX_WGF];
    int n = 0;
    File dir = SD.open(P_WG);
    if (dir && dir.isDirectory()) {
        File e;
        while ((e = dir.openNextFile()) && n < MAX_WGF) {
            String fn = String(e.name());
            int slash = fn.lastIndexOf('/');
            if (slash >= 0) fn = fn.substring(slash + 1);
            if (fn.length() > 0 && fn.endsWith(".conf")) {
                strncpy(names[n], fn.c_str(), 39);
                names[n][39] = '\0';
                ptrs[n] = names[n];
                n++;
            }
            e.close();
        }
        dir.close();
    }

    if (n == 0) {
        screenInit("WG Config Files", ",=back");
        bprint("No .conf files found!", C_WARN);
        bprint("Copy WireGuard configs", C_DIM);
        bprint("to the SD card at:", C_DIM);
        bprint("/SSHAdv/wg/", C_TITFG);
        bprint("e.g. /SSHAdv/wg/", C_DIM);
        bprint("     home.conf", C_DIM);
        bprint("Then retry.", C_DIM);
        while (waitCh() != KLEFT) {}
        return false;
    }

    int ch = pickStr(ptrs, n, "WG Config Files");
    if (ch < 0) return false;

    screenInit("Loading WG", "");
    bprintf(C_DIM, "Loading: %s", names[ch]);
    String path = String(P_WG) + "/" + names[ch];
    if (parseWGFile(path.c_str(), p)) {
        strncpy(p.wg_conffile, names[ch], sizeof(p.wg_conffile)-1);
        bprint("Parsed OK", C_OK); delay(600);
        return true;
    }
    bprint("Parse failed!", C_ERR); delay(1200);
    return false;
}


// ═══════════════════════════════════════════════════════════════════════════════
//  PROFILE DETAIL CARD
// ═══════════════════════════════════════════════════════════════════════════════

void profileCard(const Profile& p) {
    screenInit(p.name, "Enter=connect  E=edit  < back");
    M5Cardputer.Display.setTextSize(1);
    int y = BODYY + 2;
    auto row = [&](const char* label, const char* val, uint16_t vc = C_FG) {
        M5Cardputer.Display.setTextColor(C_DIM, C_BG);
        M5Cardputer.Display.setCursor(4, y);
        M5Cardputer.Display.print(label);
        M5Cardputer.Display.setTextColor(vc, C_BG);
        M5Cardputer.Display.print(val);
        y += LHS + 2;
    };
    char portBuf[8]; snprintf(portBuf, sizeof(portBuf), "%d", p.port);
    row("Host:  ", p.host, C_TITFG);
    row("Port:  ", portBuf);
    row("User:  ", p.user);

    char passBuf[68];
    if (!p.pass[0]) {
        strcpy(passBuf, "(none)");
    } else if (g_cfg.passDisplay == 2) {
        strncpy(passBuf, p.pass, sizeof(passBuf)-1);
        passBuf[sizeof(passBuf)-1] = '\0';
    } else if (g_cfg.passDisplay == 1) {
        int len = strlen(p.pass);
        int show = (len >= 3) ? 3 : len;
        int hide = len - show;
        for (int i=0; i<hide && i<60; i++) passBuf[i]='*';
        strncpy(passBuf+hide, p.pass+(len-show), show);
        passBuf[hide+show] = '\0';
    } else {
        int len = strlen(p.pass); if (len>12) len=12;
        for (int i=0;i<len;i++) passBuf[i]='*';
        passBuf[len]='\0';
    }
    row("Pass:  ", passBuf, g_cfg.passDisplay==0 ? C_DIM : C_FG);
    if (p.useWG) {
        row("WG:    ", p.wg_conffile[0] ? p.wg_conffile : "manual keys", C_WARN);
        row("Addr:  ", p.wg_addr);
    } else {
        row("WG:    ", "disabled", C_DIM);
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  PROFILE EDIT / CREATE
// ═══════════════════════════════════════════════════════════════════════════════

void editProfile(int idx) {
    bool isNew = (idx < 0);
    Profile p;
    if (isNew) { memset(&p,0,sizeof(p)); p.port=g_cfg.defaultPort; }
    else        p = g_prof[idx];

    { String v = typeText(isNew?"New Profile":"Edit Profile","Profile name:",p.name);
      if (v.isEmpty() && isNew) return;
      strncpy(p.name, v.c_str(), sizeof(p.name)-1); }

    { String v = typeText(p.name,"Host / IP:",p.host);
      strncpy(p.host, v.c_str(), sizeof(p.host)-1); }

    { const char* po[] = { "22   (SSH default)", "2222", "Custom..." };
      int cur = (p.port==22)?0:(p.port==2222)?1:2;
      int ch = pickStr(po, 3, "SSH Port", cur);
      if      (ch==0) p.port=22;
      else if (ch==1) p.port=2222;
      else if (ch==2) {
          char buf[8]; snprintf(buf,sizeof(buf),"%d",p.port);
          String v = typeText(p.name,"Port number:",buf);
          int pv=v.toInt(); p.port=(pv>0)?pv:22;
      }
    }

    { static const char* uo[MAX_USR+2];
      int n=0;
      if (p.user[0]) uo[n++]=p.user;
      for (int i=0; i<g_userCnt; i++) {
          if (!(p.user[0] && strcmp(g_users[i],p.user)==0)) uo[n++]=g_users[i];
      }
      uo[n]="Type new username...";
      int ch=pickStr(uo,n+1,"SSH User");
      if (ch>=0&&ch<n)  strncpy(p.user,uo[ch],sizeof(p.user)-1);
      else if (ch==n) {
          String v=typeText(p.name,"SSH username:",p.user);
          strncpy(p.user,v.c_str(),sizeof(p.user)-1);
          addUser(p.user);
      }
    }

    if (isNew) {
        String v = typeText(p.name, "Password:", "", true);
        strncpy(p.pass, v.c_str(), sizeof(p.pass)-1);
    } else {
        const char* po[]={ "Keep existing password","Change password" };
        int cur = p.pass[0] ? 0 : 1;
        int ch = pickStr(po, 2, "SSH Password", cur);
        if (ch == 1) {
            String v = typeText(p.name, "New password:", "", true);
            strncpy(p.pass, v.c_str(), sizeof(p.pass)-1);
        }
    }

    { const char* wo[]={ "No WireGuard","Use WireGuard" };
      int ch=pickStr(wo,2,"WireGuard",p.useWG?1:0);
      if (ch>=0) p.useWG=(ch==1);
    }

    if (p.useWG) {
        const char* wgOpts[] = { "Pick config file", "Enter keys manually" };
        int wgChoice = pickStr(wgOpts, 2, "WG config source");
        if (wgChoice == 0) {
            pickWGConf(p);
        } else if (wgChoice == 1) {
            bool reenter = true;
            if (p.wg_privkey[0])
                reenter = yesNo("WireGuard Keys","Replace existing keys?",false);
            if (reenter) {
                p.wg_privkey[0]=p.wg_addr[0]=p.wg_pubkey[0]=p.wg_endpoint[0]=p.wg_conffile[0]='\0';
                { String v=typeText("WG PrivKey","Private key:",p.wg_privkey);
                  strncpy(p.wg_privkey,v.c_str(),sizeof(p.wg_privkey)-1); }
                { String v=typeText("WG Address","IP/prefix (10.0.0.2/24):",p.wg_addr);
                  strncpy(p.wg_addr,v.c_str(),sizeof(p.wg_addr)-1); }
                { String v=typeText("WG PeerKey","Peer public key:",p.wg_pubkey);
                  strncpy(p.wg_pubkey,v.c_str(),sizeof(p.wg_pubkey)-1); }
                { String v=typeText("WG Endpoint","host:port:",p.wg_endpoint);
                  strncpy(p.wg_endpoint,v.c_str(),sizeof(p.wg_endpoint)-1); }
            }
        }
    }

    if (yesNo(p.name,"Save profile?",true)) {
        if (!isNew && strcmp(g_prof[idx].name,p.name)!=0)
            SD.remove(profPath(g_prof[idx].name).c_str());
        saveProf(p);
        if (isNew) {
            if (g_profCnt<MAX_PROF) { g_prof[g_profCnt++]=p; g_profSel=g_profCnt-1; }
        } else {
            g_prof[idx]=p;
        }
        screenInit(p.name,""); bprint("Saved!",C_OK); delay(600);
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  PROFILE LIST
// ═══════════════════════════════════════════════════════════════════════════════

void runProfileList() {
    int rows = visRows();
    int sc   = (g_profSel >= rows) ? g_profSel - rows + 1 : 0;
    static LItem items[MAX_PROF];
    int marqOff = 0;
    unsigned long lastMarq = millis();
    const unsigned long MARQ_MS = 220;

    auto build = [&]() {
        for (int i=0; i<g_profCnt; i++) {
            strncpy(items[i].label, g_prof[i].name, sizeof(items[i].label)-1);
            items[i].label[sizeof(items[i].label)-1]='\0';
            snprintf(items[i].sub, sizeof(items[i].sub), "%s:%d", g_prof[i].host, g_prof[i].port);
            items[i].lc  = C_FG;
            items[i].dot = g_prof[i].useWG ? C_WARN : C_OK;
        }
    };

    const char* HINT = ";.=nav  Ent=open  N=new  E=edit  D=del  ,=back";
    build();
    drawList(items, g_profCnt, g_profSel, sc, "Profiles", HINT, 0);

    while (true) {
        vTaskDelay(20 / portTICK_PERIOD_MS);
        checkScreenTimeout();
        M5Cardputer.update();

        bool keyPressed = M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed();
        if (keyPressed) {
            touchActivity();
            auto st = M5Cardputer.Keyboard.keysState();
            char c = '\0';
            if (st.enter) c = '\r';
            else if (st.del) c = '\b';
            else {
                for (auto ch : st.word) {
                    if ((uint8_t)ch == 0x1b) { c = KLEFT; break; }
                    c = ch; break;
                }
            }

            if (c==KUP) {
                if (g_profSel>0) {
                    g_profSel--; marqOff=0; lastMarq=millis();
                    if(g_profSel<sc) sc=g_profSel;
                    build(); drawList(items,g_profCnt,g_profSel,sc,"Profiles",HINT,0);
                }
            } else if (c==KDOWN) {
                if (g_profSel<g_profCnt-1) {
                    g_profSel++; marqOff=0; lastMarq=millis();
                    if(g_profSel>=sc+rows) sc=g_profSel-rows+1;
                    build(); drawList(items,g_profCnt,g_profSel,sc,"Profiles",HINT,0);
                }
            } else if (c=='\r'||c==KRIGHT) {
                if (g_profCnt==0) continue;
                profileCard(g_prof[g_profSel]);
                char c2=waitCh();
                if (c2=='\r'||c2==KRIGHT) runConnect(g_profSel);
                else if (c2=='e'||c2=='E') editProfile(g_profSel);
                marqOff=0; sc=(g_profSel>=rows)?g_profSel-rows+1:0;
                build(); drawList(items,g_profCnt,g_profSel,sc,"Profiles",HINT,0);
            } else if (c=='n'||c=='N') {
                editProfile(-1);
                marqOff=0; sc=(g_profSel>=rows)?g_profSel-rows+1:0;
                build(); drawList(items,g_profCnt,g_profSel,sc,"Profiles",HINT,0);
            } else if (c=='e'||c=='E') {
                if (g_profCnt>0) {
                    editProfile(g_profSel);
                    marqOff=0; sc=(g_profSel>=rows)?g_profSel-rows+1:0;
                    build(); drawList(items,g_profCnt,g_profSel,sc,"Profiles",HINT,0);
                }
            } else if (c=='d'||c=='D') {
                if (g_profCnt>0) {
                    char q[48]; snprintf(q,sizeof(q),"Delete '%s'?",g_prof[g_profSel].name);
                    if (yesNo("Delete",q,false)) {
                        deleteProf(g_profSel);
                        marqOff=0; sc=(g_profSel>=rows)?g_profSel-rows+1:0;
                    }
                    build(); drawList(items,g_profCnt,g_profSel,sc,"Profiles",HINT,0);
                }
            } else if (c==KLEFT) { return; }
        }

        if (millis()-lastMarq >= MARQ_MS) {
            lastMarq=millis();
            if (g_profCnt > 0) {
                int lblLen  = strlen(items[g_profSel].label);
                int maxCols = labelCols(items[g_profSel].sub[0]!='\0');
                if (lblLen > maxCols) {
                    marqOff++;
                    redrawSelRow(items,g_profCnt,g_profSel,sc,"Profiles",HINT,marqOff);
                }
            }
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  WIFI
// ═══════════════════════════════════════════════════════════════════════════════

void doConnect(const String& ssid, const String& pw) {
    screenInit("WiFi","");
    char ssbuf[20]; strncpy(ssbuf, ssid.c_str(), 19); ssbuf[19]='\0';
    bprintf(C_DIM,"Connecting: %s", ssbuf);
    WiFi.begin(ssid.c_str(), pw.c_str());
    for (int i=0; i<30 && WiFi.status()!=WL_CONNECTED; i++) {
        vTaskDelay(400/portTICK_PERIOD_MS); M5Cardputer.Display.print('.');
    }
    M5Cardputer.Display.println();
    if (WiFi.status()==WL_CONNECTED) {
        g_wifiOk=true;
        strncpy(g_ssid, ssid.c_str(), sizeof(g_ssid)-1);
        strncpy(g_wpass, pw.c_str(), sizeof(g_wpass)-1);
        bprint("Connected!", C_OK); delay(400);
        if (yesNo("WiFi","Save credentials?",true)) saveWifi();
    } else {
        bprint("Failed.", C_ERR); delay(1200);
    }
}

void runWifiScan() {
    screenInit("WiFi Scan", "");
    bprint("Scanning...", C_DIM);

    WiFi.mode(WIFI_STA);
    WiFi.disconnect(true);
    vTaskDelay(500 / portTICK_PERIOD_MS);

    int found = WiFi.scanNetworks(false, true);

    if (found <= 0) {
        bprint("", C_DIM);
        bprint(found == 0 ? "No networks found." : "Scan failed.", found == 0 ? C_WARN : C_ERR);
        bprint("< to go back", C_DIM);
        while (waitCh() != KLEFT) {}
        WiFi.scanDelete();
        return;
    }
    if (found > MAX_NET) found = MAX_NET;

    static LItem items[MAX_NET];
    static char ssids[MAX_NET][44];
    static wifi_auth_mode_t encs[MAX_NET];
    for (int i = 0; i < found; i++) {
        strncpy(items[i].label, WiFi.SSID(i).c_str(), sizeof(items[i].label)-1);
        items[i].label[sizeof(items[i].label)-1] = '\0';
        strncpy(ssids[i], items[i].label, sizeof(ssids[i])-1);
        snprintf(items[i].sub, sizeof(items[i].sub), "%ddBm", WiFi.RSSI(i));
        items[i].lc  = C_FG;
        encs[i] = WiFi.encryptionType(i);
        items[i].dot = (encs[i] == WIFI_AUTH_OPEN) ? C_OK : C_WARN;
    }
    WiFi.scanDelete();

    int ch = runList(items, found, "Select Network", "^ v = move   Enter = pick   < back");
    if (ch < 0) return;
    String ssid = ssids[ch];
    String pw = "";
    if (encs[ch] != WIFI_AUTH_OPEN)
        pw = typeText("WiFi Password", ssid.c_str(), "", true);
    doConnect(ssid, pw);
}

void runWifiMenu() {
    while (true) {
        static char item0[32];
        if (g_wifiOk) {
            char ssbuf[11]; strncpy(ssbuf,g_ssid,10); ssbuf[10]='\0';
            snprintf(item0,sizeof(item0),"Scan (%s)",ssbuf);
        } else {
            snprintf(item0,sizeof(item0),"Scan networks");
        }
        const char* opts[4]; int n=0;
        opts[n++]=item0;
        opts[n++]="Enter SSID manually";
        if (g_wifiOk) opts[n++]="Disconnect";
        opts[n++]="Back";

        int ch=pickStr(opts,n,"WiFi");
        if (ch<0||strcmp(opts[ch],"Back")==0) return;
        if      (strncmp(opts[ch],"Scan",4)==0)            runWifiScan();
        else if (strcmp(opts[ch],"Enter SSID manually")==0) {
            String ssid=typeText("WiFi Manual","SSID:");
            String pw  =typeText("WiFi Manual","Password:","",true);
            doConnect(ssid,pw);
        } else if (strcmp(opts[ch],"Disconnect")==0) {
            WiFi.disconnect(true); g_wifiOk=false;
            screenInit("WiFi",""); bprint("Disconnected.",C_DIM); delay(800);
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SETTINGS
// ═══════════════════════════════════════════════════════════════════════════════

void runSettings() {
    const char* cats[] = { "Display", "Terminal", "Connection", "Security", "< Back" };
    while (true) {
        int cat = pickStr(cats, 5, "Settings");
        if (cat < 0 || cat == 4) return;

        if (cat == 0) {
            while (true) {
                char scrBuf[32], brtBuf[32];
                if (g_cfg.screenTimeoutSec <= 0) snprintf(scrBuf, sizeof(scrBuf), "Screen dim  Never");
                else snprintf(scrBuf, sizeof(scrBuf), "Screen dim  %ds", g_cfg.screenTimeoutSec);
                snprintf(brtBuf, sizeof(brtBuf), "Brightness  %d%%", g_cfg.brightness * 100 / 255);
                const char* opts[] = { scrBuf, brtBuf, "< Back" };
                int ch = pickStr(opts, 3, "Display");
                if (ch < 0 || ch == 2) break;
                if (ch == 0) {
                    const char* sc[] = { "Never","10s","30s","1min","2min","5min","10min" };
                    int vals[] = { 0,10,30,60,120,300,600 };
                    int cur = 0; for (int i=0;i<7;i++) if(vals[i]==g_cfg.screenTimeoutSec){cur=i;break;}
                    int p = pickStr(sc, 7, "Screen Dim", cur);
                    if (p >= 0) { g_cfg.screenTimeoutSec = vals[p]; saveSettings(); }
                } else if (ch == 1) {
                    const char* sc[] = { "25%","50%","75%","100%" };
                    int vals[] = { 64,128,192,255 };
                    int cur = 1; for (int i=0;i<4;i++) if(abs(vals[i]-g_cfg.brightness)<32){cur=i;break;}
                    int p = pickStr(sc, 4, "Brightness", cur);
                    if (p >= 0) { g_cfg.brightness=vals[p]; M5Cardputer.Display.setBrightness(g_cfg.brightness); saveSettings(); }
                }
            }

        } else if (cat == 1) {
            while (true) {
                char fntBuf[32], buzBuf[32];
                snprintf(fntBuf, sizeof(fntBuf), "Font size   %d", g_cfg.termFontSize);
                snprintf(buzBuf, sizeof(buzBuf), "Buzzer      %s", g_cfg.buzzer ? "On" : "Off");
                const char* opts[] = { fntBuf, buzBuf, "< Back" };
                int ch = pickStr(opts, 3, "Terminal");
                if (ch < 0 || ch == 2) break;
                if (ch == 0) {
                    const char* sc[] = { "1  (more text)", "2  (larger)" };
                    int p = pickStr(sc, 2, "Font Size", g_cfg.termFontSize == 2 ? 1 : 0);
                    if (p >= 0) { g_cfg.termFontSize = (p == 1) ? 2 : 1; saveSettings(); }
                } else if (ch == 1) {
                    const char* sc[] = { "Off", "On" };
                    int p = pickStr(sc, 2, "Buzzer", g_cfg.buzzer ? 1 : 0);
                    if (p >= 0) { g_cfg.buzzer = (p == 1); saveSettings(); }
                }
            }

        } else if (cat == 2) {
            while (true) {
                char sshBuf[32], wfiBuf[32], kaBuf[32], portBuf[32], acBuf[32];
                if (g_cfg.sshTimeoutMin <= 0) snprintf(sshBuf, sizeof(sshBuf), "SSH idle    Never");
                else snprintf(sshBuf, sizeof(sshBuf), "SSH idle    %dmin", g_cfg.sshTimeoutMin);
                if (g_cfg.wifiTimeoutMin <= 0) snprintf(wfiBuf, sizeof(wfiBuf), "WiFi retry  Never");
                else snprintf(wfiBuf, sizeof(wfiBuf), "WiFi retry  %dmin", g_cfg.wifiTimeoutMin);
                snprintf(kaBuf,   sizeof(kaBuf),   "Keepalive   %s", g_cfg.keepAlive ? "On" : "Off");
                snprintf(portBuf, sizeof(portBuf), "Default port %d", g_cfg.defaultPort);
                snprintf(acBuf,   sizeof(acBuf),   "Auto WiFi   %s", g_cfg.autoConnect ? "On" : "Off");
                const char* opts[] = { sshBuf, wfiBuf, kaBuf, portBuf, acBuf, "< Back" };
                int ch = pickStr(opts, 6, "Connection");
                if (ch < 0 || ch == 5) break;
                if (ch == 0) {
                    const char* sc[] = { "Never","5min","10min","30min","1hr","2hr" };
                    int vals[] = { 0,5,10,30,60,120 };
                    int cur = 0; for (int i=0;i<6;i++) if(vals[i]==g_cfg.sshTimeoutMin){cur=i;break;}
                    int p = pickStr(sc, 6, "SSH Idle Timeout", cur);
                    if (p >= 0) { g_cfg.sshTimeoutMin = vals[p]; saveSettings(); }
                } else if (ch == 1) {
                    const char* sc[] = { "Never","1min","5min","15min","30min" };
                    int vals[] = { 0,1,5,15,30 };
                    int cur = 0; for (int i=0;i<5;i++) if(vals[i]==g_cfg.wifiTimeoutMin){cur=i;break;}
                    int p = pickStr(sc, 5, "WiFi Retry", cur);
                    if (p >= 0) { g_cfg.wifiTimeoutMin = vals[p]; saveSettings(); }
                } else if (ch == 2) {
                    const char* sc[] = { "On (recommended)", "Off" };
                    int p = pickStr(sc, 2, "SSH Keepalive", g_cfg.keepAlive ? 0 : 1);
                    if (p >= 0) { g_cfg.keepAlive = (p == 0); saveSettings(); }
                } else if (ch == 3) {
                    const char* sc[] = { "22 (SSH)", "443 (HTTPS)", "2222", "Custom" };
                    int vals[] = { 22,443,2222,0 };
                    int cur = 0; for (int i=0;i<3;i++) if(vals[i]==g_cfg.defaultPort){cur=i;break;}
                    int p = pickStr(sc, 4, "Default SSH Port", cur);
                    if (p == 3) {
                        char buf[8]; snprintf(buf, sizeof(buf), "%d", g_cfg.defaultPort);
                        String v = typeText("Custom Port", "Port:", buf);
                        int pv = v.toInt(); if (pv > 0) { g_cfg.defaultPort = pv; saveSettings(); }
                    } else if (p >= 0) { g_cfg.defaultPort = vals[p]; saveSettings(); }
                } else if (ch == 4) {
                    const char* sc[] = { "On (connect at boot)", "Off" };
                    int p = pickStr(sc, 2, "Auto-connect WiFi", g_cfg.autoConnect ? 0 : 1);
                    if (p >= 0) { g_cfg.autoConnect = (p == 0); saveSettings(); }
                }
            }

        } else if (cat == 3) {
            while (true) {
                const char* pdNames[] = { "Hidden (****)", "Last 3 chars", "Visible" };
                char pdBuf[32];
                snprintf(pdBuf, sizeof(pdBuf), "Passwords   %s", pdNames[g_cfg.passDisplay]);
                const char* opts[] = { pdBuf, "< Back" };
                int ch = pickStr(opts, 2, "Security");
                if (ch < 0 || ch == 1) break;
                if (ch == 0) {
                    int p = pickStr(pdNames, 3, "Password Display", g_cfg.passDisplay);
                    if (p >= 0) { g_cfg.passDisplay = p; saveSettings(); }
                }
            }
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  HOME SCREEN
// ═══════════════════════════════════════════════════════════════════════════════

void drawWifiIcon(int cx, int cy, uint16_t col) {
    M5Cardputer.Display.fillCircle(cx, cy, 3, col);
    M5Cardputer.Display.drawArc(cx, cy,  8,  6, 225, 315, col);
    M5Cardputer.Display.drawArc(cx, cy, 14, 12, 225, 315, col);
    M5Cardputer.Display.drawArc(cx, cy, 20, 18, 225, 315, col);
}

void drawSshIcon(int cx, int cy, uint16_t col, uint16_t bg) {
    M5Cardputer.Display.drawRoundRect(cx-22, cy-12, 44, 26, 4, col);
    M5Cardputer.Display.setTextSize(2);
    M5Cardputer.Display.setTextColor(col, bg);
    M5Cardputer.Display.setCursor(cx-18, cy-8); M5Cardputer.Display.print(">_");
}

void drawGearIcon(int cx, int cy, uint16_t col) {
    M5Cardputer.Display.drawCircle(cx, cy, 12, col);
    M5Cardputer.Display.drawCircle(cx, cy, 5,  col);
    for (int a = 0; a < 360; a += 60) {
        float r = a * 3.14159f / 180.0f;
        int x1 = cx + (int)(12 * cosf(r));
        int y1 = cy + (int)(12 * sinf(r));
        int x2 = cx + (int)(16 * cosf(r));
        int y2 = cy + (int)(16 * sinf(r));
        M5Cardputer.Display.drawLine(x1, y1, x2, y2, col);
    }
}

void drawHome(int sel) {
    M5Cardputer.Display.fillScreen(C_BG);

    uint16_t tileColors[3] = {C_WIFI, C_PROF, C_SETT};
    const char* labels[] = {"WiFi", "Profiles", "Settings"};
    uint16_t col = tileColors[sel];

    if (sel > 0) {
        int ax = DW/2;
        for (int i = 0; i < 7; i++)
            M5Cardputer.Display.drawLine(ax-i, 6+i, ax+i, 6+i, C_DIM);
    }
    if (sel < 2) {
        int ax = DW/2;
        for (int i = 0; i < 7; i++)
            M5Cardputer.Display.drawLine(ax-(6-i), 104+i, ax+(6-i), 104+i, C_DIM);
    }

    for (int i = 0; i < 3; i++) {
        int dx = DW - 8;
        int dy = 58 - 16 + i*16;
        if (i == sel) M5Cardputer.Display.fillCircle(dx, dy, 4, col);
        else          M5Cardputer.Display.drawCircle(dx, dy, 3, C_DIM);
    }

    int cx = DW / 2;
    int cy = 47;
    if (sel == 0)      drawWifiIcon(cx, cy, col);
    else if (sel == 1) drawSshIcon(cx, cy, col, C_BG);
    else               drawGearIcon(cx, cy, col);

    M5Cardputer.Display.setTextSize(2);
    M5Cardputer.Display.setTextColor(col, C_BG);
    int lw = strlen(labels[sel]) * 12;
    M5Cardputer.Display.setCursor(cx - lw/2, cy + 22);
    M5Cardputer.Display.print(labels[sel]);

    const int SHBAR = 18;
    int y = DH - SHBAR;
    M5Cardputer.Display.fillRect(0, y, DW, SHBAR, C_HNTBG);
    M5Cardputer.Display.setTextSize(2);
    M5Cardputer.Display.setCursor(3, y + 1);
    if (g_wifiOk) {
        char ssbuf[18]; strncpy(ssbuf, g_ssid, 17); ssbuf[17]='\0';
        char hbuf[36]; snprintf(hbuf, sizeof(hbuf), " WiFi: %s", ssbuf);
        M5Cardputer.Display.setTextColor(C_OK, C_HNTBG);
        M5Cardputer.Display.print(hbuf);
    } else {
        M5Cardputer.Display.setTextColor(C_ERR, C_HNTBG);
        M5Cardputer.Display.print(" Not connected");
    }
}

void runHome() {
    int sel = 0;
    while (true) {
        drawHome(sel);
        char c = waitCh();
        if (c==KUP)   { if(sel>0) sel--; }
        if (c==KDOWN) { if(sel<2) sel++; }
        if (c=='\r')  {
            if (sel==0) runWifiMenu();
            if (sel==1) runProfileList();
            if (sel==2) runSettings();
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  CONNECT  (WireGuard + SSH)
// ═══════════════════════════════════════════════════════════════════════════════

static void sshConnectTask(void* arg) {
    SSHTaskCtx* ctx = (SSHTaskCtx*)arg;
    const Profile& p = ctx->prof;

    ctx->sess = ssh_new();
    if (!ctx->sess) {
        strlcpy(ctx->errmsg, "ssh_new failed", sizeof(ctx->errmsg));
        ctx->state = 2; vTaskDelete(NULL); return;
    }

    int verb = SSH_LOG_NOLOG, port = p.port, timeout = 30;
    ssh_options_set(ctx->sess, SSH_OPTIONS_HOST, p.host);
    ssh_options_set(ctx->sess, SSH_OPTIONS_USER, p.user);
    ssh_options_set(ctx->sess, SSH_OPTIONS_PORT, &port);
    ssh_options_set(ctx->sess, SSH_OPTIONS_LOG_VERBOSITY, &verb);
    ssh_options_set(ctx->sess, SSH_OPTIONS_TIMEOUT, &timeout);

    if (g_taskAbort || ssh_connect(ctx->sess) != SSH_OK) {
        if (g_taskAbort) strlcpy(ctx->errmsg, "Aborted", sizeof(ctx->errmsg));
        else snprintf(ctx->errmsg, sizeof(ctx->errmsg), "Conn: %s", ssh_get_error(ctx->sess));
        ssh_free(ctx->sess); ctx->sess = nullptr;
        ctx->state = 2; vTaskDelete(NULL); return;
    }

    // Enable TCP keepalive on the socket to prevent NAT/firewall timeouts
    if (g_cfg.keepAlive) {
        socket_t fd = ssh_get_fd(ctx->sess);
        if (fd >= 0) {
            int yes = 1;
            int idle = 60;    // first keepalive after 60s idle
            int intvl = 15;   // retry every 15s
            int cnt = 4;      // drop after 4 missed replies
            setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
        }
    }

    if (ssh_userauth_password(ctx->sess, nullptr, p.pass) != SSH_AUTH_SUCCESS) {
        strlcpy(ctx->errmsg, "Auth failed", sizeof(ctx->errmsg));
        ssh_disconnect(ctx->sess); ssh_free(ctx->sess); ctx->sess = nullptr;
        ctx->state = 2; vTaskDelete(NULL); return;
    }

    ctx->ch = ssh_channel_new(ctx->sess);
    int termCols = (g_cfg.termFontSize == 2) ? 20 : 40;
    int termRows = (g_cfg.termFontSize == 2) ?  7 : 14;

    if (!ctx->ch ||
        ssh_channel_open_session(ctx->ch) != SSH_OK ||
        ssh_channel_request_pty_size(ctx->ch, "xterm", termCols, termRows) != SSH_OK ||
        ssh_channel_request_shell(ctx->ch) != SSH_OK) {
        strlcpy(ctx->errmsg, "Shell open failed", sizeof(ctx->errmsg));
        if (ctx->ch) { ssh_channel_free(ctx->ch); ctx->ch = nullptr; }
        ssh_disconnect(ctx->sess); ssh_free(ctx->sess); ctx->sess = nullptr;
        ctx->state = 2; vTaskDelete(NULL); return;
    }

    ctx->state = 1;
    vTaskDelete(NULL);
}

void runConnect(int idx) {
    g_sshCtx.prof  = g_prof[idx];
    g_sshCtx.sess  = nullptr;
    g_sshCtx.ch    = nullptr;
    g_sshCtx.state = 0;
    g_sshCtx.errmsg[0] = '\0';

    const Profile& p = g_sshCtx.prof;
    screenInit(p.name, "");

    // WireGuard setup
    if (p.useWG) {
        char newFp[128];
        wgFingerprint(p, newFp, sizeof(newFp));
        bool same = (g_wg != nullptr && strcmp(newFp, g_wgFingerprint) == 0);
        if (same) {
            bprint("WG resuming...", C_DIM);
            wgResume();
            bprint("WG up.", C_OK);
        } else if (g_wg == nullptr) {
            bprint("WireGuard...", C_DIM);
            if (!wgStart(p, newFp)) return;
        } else {
            // Different WG config — clean teardown only if TCP hasn't used the tunnel
            if (!g_wgTcpUsed) {
                bprint("Switching WG...", C_DIM);
                g_wg->end(); delete g_wg;
                g_wg = nullptr; g_wgNetif = nullptr; g_wgFingerprint[0] = '\0';
                vTaskDelay(400 / portTICK_PERIOD_MS);
                if (!wgStart(p, newFp)) return;
            } else {
                // TCP touched the netif — end() would crash lwIP. Restart instead.
                bprint("Switching WG...", C_DIM);
                delay(600);
                g_bootProfileIdx = idx;
                ESP.restart();
            }
        }
    } else {
        if (g_wg) wgSuspend();
    }

    bprint("SSH connecting...", C_DIM);
    g_taskAbort = false;
    g_sshTask   = nullptr;
    xTaskCreatePinnedToCore(sshConnectTask, "ssh_conn", 32768,
                            &g_sshCtx, 5, &g_sshTask, 0);
    if (!g_sshTask) {
        bprint("Task create failed!", C_ERR); delay(2000); return;
    }

    unsigned long t0 = millis();
    while (g_sshCtx.state == 0) {
        if ((millis() - t0) > 30000UL) {
            bprint("Timeout!", C_ERR);
            g_taskAbort = true;
            while (g_sshTask != nullptr && eTaskGetState(g_sshTask) != eDeleted)
                vTaskDelay(50 / portTICK_PERIOD_MS);
            g_sshTask = nullptr;
            delay(500);
            wgSuspend();
            return;
        }
        M5Cardputer.update();
        if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
            auto st = M5Cardputer.Keyboard.keysState();
            for (auto ch : st.word) {
                if (ch == KLEFT || (uint8_t)ch == 0x1b) {
                    bprint("Cancelled.", C_DIM);
                    g_taskAbort = true;
                    while (g_sshTask != nullptr && eTaskGetState(g_sshTask) != eDeleted)
                        vTaskDelay(50 / portTICK_PERIOD_MS);
                    g_sshTask = nullptr;
                    delay(300);
                    wgSuspend();
                    return;
                }
            }
        }
        vTaskDelay(200 / portTICK_PERIOD_MS);
        M5Cardputer.Display.print('.');
    }
    g_sshTask = nullptr;

    if (g_sshCtx.state == 2) {
        bprintf(C_ERR, "%s", g_sshCtx.errmsg);
        delay(2500);
        wgSuspend();
        return;
    }

    if (p.useWG) g_wgTcpUsed = true;
    ssh_session sess = g_sshCtx.sess;
    ssh_channel ch   = g_sshCtx.ch;

    M5Cardputer.Display.fillScreen(C_BG);
    titleBar(p.name);

    runSSHTerm(sess, ch);

    if (ch) {
        ssh_channel_send_eof(ch);
        ssh_channel_close(ch);
        ssh_channel_free(ch);
    }
    if (sess) {
        ssh_disconnect(sess);
        ssh_free(sess);
    }
    g_sshCtx.sess = nullptr;
    g_sshCtx.ch   = nullptr;
    g_sshCtx.state = 0;

    vTaskDelay(500 / portTICK_PERIOD_MS);
    wgSuspend();
    screenInit(p.name, "Any key to return");
    bprint("Session ended.", C_DIM);
    waitCh();
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SSH TERMINAL
// ═══════════════════════════════════════════════════════════════════════════════

struct TCell {
    char     ch;
    uint16_t fg;
    uint16_t bg;
    bool     bold;
};

void runSSHTerm(ssh_session sess, ssh_channel ch) {
    const int TOP  = TITLEH + 2;
    const int BOT  = DH - HINTH;

    const int MAXCOLS = 40;
    const int MAXROWS = 14;

    static TCell tbuf[2][MAXROWS][MAXCOLS];
    static int   tcx, tcy;
    static int   savedCx, savedCy;
    static int   tCols, tRows;
    static int   scrollTop, scrollBot;
    static bool  altScreen;

    auto lh       = [&]() { return g_cfg.termFontSize * 8; };
    auto termCols = [&]() { return (g_cfg.termFontSize == 2) ? 20 : 40; };
    auto termRows = [&]() { return (g_cfg.termFontSize == 2) ?  7 : 14; };
    auto cw       = [&]() { return g_cfg.termFontSize * 6; };
    auto rowY     = [&](int r) { return TOP + r * lh(); };
    auto activeBuf= [&]() -> TCell(*)[MAXCOLS] { return tbuf[altScreen ? 1 : 0]; };

    static const uint16_t ansiCol[16] = {
        0x0000, 0x8000, 0x0400, 0x8400, 0x0010, 0x8010, 0x0410, 0xC618,
        0x4208, 0xF800, 0x07E0, 0xFFE0, 0x001F, 0xF81F, 0x07FF, 0xFFFF
    };

    static uint16_t curFg, curBg;
    static bool     curBold;

    auto drawCell = [&](int col, int row) {
        auto& cell = activeBuf()[row][col];
        int px = col * cw(), py = rowY(row);
        M5Cardputer.Display.fillRect(px, py, cw(), lh(), cell.bg);
        if (cell.ch && cell.ch != ' ') {
            M5Cardputer.Display.setTextColor(cell.fg, cell.bg);
            M5Cardputer.Display.setCursor(px, py);
            M5Cardputer.Display.write(cell.ch);
        }
    };

    auto drawRow = [&](int row) {
        M5Cardputer.Display.fillRect(0, rowY(row), DW, lh(), C_BG);
        for (int c2 = 0; c2 < tCols; c2++) {
            auto& cell = activeBuf()[row][c2];
            if (cell.ch && cell.ch != ' ') {
                M5Cardputer.Display.setTextColor(cell.fg, cell.bg);
                M5Cardputer.Display.setCursor(c2 * cw(), rowY(row));
                M5Cardputer.Display.write(cell.ch);
            }
        }
    };

    auto redrawAll = [&]() {
        M5Cardputer.Display.fillRect(0, TOP, DW, BOT - TOP, C_BG);
        for (int r = 0; r < tRows; r++) drawRow(r);
        M5Cardputer.Display.setTextColor(C_FG, C_BG);
    };

    auto scrollRegionUp = [&](int n2, int fromRow = -1) {
        if (fromRow < 0) fromRow = scrollTop;
        for (int rep = 0; rep < n2; rep++) {
            for (int r = fromRow; r < scrollBot; r++)
                memcpy(activeBuf()[r], activeBuf()[r+1], sizeof(TCell)*MAXCOLS);
            memset(activeBuf()[scrollBot], 0, sizeof(TCell)*MAXCOLS);
            for (int c2 = 0; c2 < tCols; c2++)
                activeBuf()[scrollBot][c2] = {0, curFg, curBg, false};
        }
        redrawAll();
    };

    auto scrollRegionDown = [&](int n2, int fromRow = -1) {
        if (fromRow < 0) fromRow = scrollTop;
        for (int rep = 0; rep < n2; rep++) {
            for (int r = scrollBot; r > fromRow; r--)
                memcpy(activeBuf()[r], activeBuf()[r-1], sizeof(TCell)*MAXCOLS);
            memset(activeBuf()[fromRow], 0, sizeof(TCell)*MAXCOLS);
            for (int c2 = 0; c2 < tCols; c2++)
                activeBuf()[fromRow][c2] = {0, curFg, curBg, false};
        }
        redrawAll();
    };

    auto clearBuf = [&](int bufIdx) {
        for (int r = 0; r < MAXROWS; r++)
            for (int c2 = 0; c2 < MAXCOLS; c2++)
                tbuf[bufIdx][r][c2] = {0, C_FG, C_BG, false};
    };

    auto putChar = [&](char c2) {
        if (tcx >= tCols) {
            tcx = 0; tcy++;
            if (tcy > scrollBot) { scrollRegionUp(1); tcy = scrollBot; }
        }
        if (tcy >= tRows) tcy = tRows - 1;
        activeBuf()[tcy][tcx] = {c2, curFg, curBg, curBold};
        drawCell(tcx, tcy);
        tcx++;
    };

    // Init
    tCols = termCols(); tRows = termRows();
    scrollTop = 0; scrollBot = tRows - 1;
    altScreen = false;
    tcx = tcy = savedCx = savedCy = 0;
    curFg = C_FG; curBg = C_BG; curBold = false;
    clearBuf(0); clearBuf(1);
    M5Cardputer.Display.fillRect(0, TOP, DW, BOT - TOP, C_BG);

    auto showHint = [&]() {
        hintBar("G0/Fn+Q=quit  Fn+;.,/=arrows  Fn+F=font");
        M5Cardputer.Display.setTextSize(g_cfg.termFontSize);
        M5Cardputer.Display.setTextColor(C_FG, C_BG);
    };
    showHint();

    // ANSI parser state
    static bool  inEsc = false, inCSI = false, inOSC = false;
    static char  csiBuf[64];
    static int   csiLen = 0;
    static bool  csiPriv = false;
    inEsc = false; inCSI = false; inOSC = false; csiLen = 0; csiPriv = false;

    unsigned long sshLastActivity  = millis();

    while (true) {
        vTaskDelay(8 / portTICK_PERIOD_MS);
        M5Cardputer.update();

        if (M5Cardputer.BtnA.wasPressed()) break;

        if (g_cfg.sshTimeoutMin > 0 &&
            (millis() - sshLastActivity) > (unsigned long)g_cfg.sshTimeoutMin * 60000UL)
            break;

        if (g_cfg.screenTimeoutSec > 0 && !g_dimmed &&
            (millis() - g_lastAct) > (unsigned long)g_cfg.screenTimeoutSec * 1000UL) {
            M5Cardputer.Display.setBrightness(0);
            g_dimmed = true;
        }

        // Keyboard
        if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
            unsigned long now = millis();
            if (now - g_lastKey >= DEBOUNCE_MS) {
                g_lastKey = now;
                touchActivity();
                sshLastActivity = now;
                auto st = M5Cardputer.Keyboard.keysState();

                if (isFn()) {
                    for (auto hid : st.hid_keys) {
                        char a = hidToAlpha(hid);
                        if (a == 'q') goto done;
                        if (a == 'f') {
                            g_cfg.termFontSize = (g_cfg.termFontSize == 1) ? 2 : 1;
                            saveSettings();
                            tCols = termCols(); tRows = termRows();
                            scrollTop = 0; scrollBot = tRows - 1;
                            clearBuf(0); clearBuf(1);
                            M5Cardputer.Display.fillRect(0, TOP, DW, BOT - TOP, C_BG);
                            showHint();
                            ssh_channel_change_pty_size(ch, tCols, tRows);
                        }
                        if (hid == 0x33) ssh_channel_write(ch, "\x1b[A", 3);
                        if (hid == 0x37) ssh_channel_write(ch, "\x1b[B", 3);
                        if (hid == 0x36) ssh_channel_write(ch, "\x1b[D", 3);
                        if (hid == 0x38) ssh_channel_write(ch, "\x1b[C", 3);
                    }
                } else if (isCtrl()) {
                    for (auto hid : st.hid_keys) {
                        char a = hidToAlpha(hid);
                        if (a) { char cc = a - 'a' + 1; ssh_channel_write(ch, &cc, 1); }
                        if (hid == 0x2F) { const char e = 0x1B; ssh_channel_write(ch, &e, 1); }
                    }
                } else {
                    for (auto c2 : st.word) {
                        if ((uint8_t)c2 == 0x1B) { ssh_channel_write(ch, "\x1b", 1); continue; }
                        ssh_channel_write(ch, &c2, 1);
                    }
                    if (st.del)   { char bs = 0x7F; ssh_channel_write(ch, &bs, 1); }
                    if (st.enter) { const char cr = '\r'; ssh_channel_write(ch, &cr, 1); }
                    for (auto hid : st.hid_keys) {
                        if (hid == 0x2B) { const char tab = '\t'; ssh_channel_write(ch, &tab, 1); }
                    }
                }
            }
        }

        // Receive & render
        char rbuf[256];
        int n = ssh_channel_read_nonblocking(ch, rbuf, sizeof(rbuf), 0);
        if (n > 0) {
            sshLastActivity = millis();
            for (int i = 0; i < n; i++) {
                uint8_t c2 = rbuf[i];

                if (inOSC) {
                    if (c2 == 0x07 || c2 == 0x9C) inOSC = false;
                    else if (c2 == 0x1B) { inOSC = false; inEsc = true; }
                    continue;
                }

                if (inCSI) {
                    if (c2 >= 0x40 && c2 <= 0x7E) {
                        csiBuf[csiLen] = '\0';
                        inCSI = false;

                        int p[8]; int pc = 0;
                        memset(p, -1, sizeof(p));
                        char* s = csiBuf;
                        while (*s && pc < 8) {
                            if (*s >= '0' && *s <= '9') {
                                p[pc] = atoi(s);
                                while (*s >= '0' && *s <= '9') s++;
                                pc++;
                            } else if (*s == ';') {
                                if (p[pc] < 0) p[pc] = 0;
                                pc++;
                                s++;
                            } else s++;
                        }
                        auto P1 = [&](int def) { return (p[0] < 0) ? def : p[0]; };
                        auto P2 = [&](int def) { return (p[1] < 0) ? def : p[1]; };

                        if (csiPriv) {
                            if (c2 == 'h' || c2 == 'l') {
                                bool set = (c2 == 'h');
                                int mode = P1(0);
                                if (mode == 25) {
                                } else if (mode == 1049 || mode == 47 || mode == 1047) {
                                    if (set && !altScreen) {
                                        altScreen = true;
                                        savedCx = tcx; savedCy = tcy;
                                        tcx = tcy = 0;
                                        clearBuf(1);
                                        redrawAll();
                                    } else if (!set && altScreen) {
                                        altScreen = false;
                                        tcx = savedCx; tcy = savedCy;
                                        redrawAll();
                                    }
                                }
                            }
                            csiPriv = false; csiLen = 0;
                            continue;
                        }

                        switch (c2) {
                            case 'A': { int n2=(P1(1)); tcy-=n2; if(tcy<scrollTop)tcy=scrollTop; break; }
                            case 'B': { int n2=(P1(1)); tcy+=n2; if(tcy>scrollBot)tcy=scrollBot; break; }
                            case 'C': { int n2=(P1(1)); tcx+=n2; if(tcx>=tCols)tcx=tCols-1; break; }
                            case 'D': { int n2=(P1(1)); tcx-=n2; if(tcx<0)tcx=0; break; }
                            case 'E': { int n2=(P1(1)); tcy+=n2; tcx=0; if(tcy>scrollBot)tcy=scrollBot; break; }
                            case 'F': { int n2=(P1(1)); tcy-=n2; tcx=0; if(tcy<scrollTop)tcy=scrollTop; break; }
                            case 'G': { tcx = P1(1)-1; if(tcx<0)tcx=0; if(tcx>=tCols)tcx=tCols-1; break; }
                            case 'H': case 'f': {
                                tcy = P1(1)-1; tcx = P2(1)-1;
                                if(tcy<0)tcy=0; if(tcy>=tRows)tcy=tRows-1;
                                if(tcx<0)tcx=0; if(tcx>=tCols)tcx=tCols-1;
                                break;
                            }
                            case 'd': { tcy = P1(1)-1; if(tcy<0)tcy=0; if(tcy>=tRows)tcy=tRows-1; break; }
                            case 'J': {
                                int arg=P1(0);
                                if (arg==0) {
                                    for(int x=tcx;x<tCols;x++) activeBuf()[tcy][x]={0,curFg,curBg,false};
                                    M5Cardputer.Display.fillRect(tcx*cw(), rowY(tcy), DW-tcx*cw(), lh(), curBg);
                                    for(int r=tcy+1;r<tRows;r++){
                                        memset(activeBuf()[r],0,sizeof(TCell)*MAXCOLS);
                                        for(int x=0;x<tCols;x++) activeBuf()[r][x]={0,curFg,curBg,false};
                                        M5Cardputer.Display.fillRect(0,rowY(r),DW,lh(),curBg);
                                    }
                                } else if (arg==1) {
                                    for(int r=0;r<tcy;r++){
                                        memset(activeBuf()[r],0,sizeof(TCell)*MAXCOLS);
                                        for(int x=0;x<tCols;x++) activeBuf()[r][x]={0,curFg,curBg,false};
                                        M5Cardputer.Display.fillRect(0,rowY(r),DW,lh(),curBg);
                                    }
                                    for(int x=0;x<=tcx;x++) activeBuf()[tcy][x]={0,curFg,curBg,false};
                                    M5Cardputer.Display.fillRect(0,rowY(tcy),(tcx+1)*cw(),lh(),curBg);
                                } else {
                                    clearBuf(altScreen?1:0);
                                    M5Cardputer.Display.fillRect(0,TOP,DW,BOT-TOP,curBg);
                                    tcx=tcy=0;
                                }
                                break;
                            }
                            case 'K': {
                                int arg=P1(0);
                                if (arg==0) {
                                    for(int x=tcx;x<tCols;x++) activeBuf()[tcy][x]={0,curFg,curBg,false};
                                    M5Cardputer.Display.fillRect(tcx*cw(),rowY(tcy),DW-tcx*cw(),lh(),curBg);
                                } else if (arg==1) {
                                    for(int x=0;x<=tcx;x++) activeBuf()[tcy][x]={0,curFg,curBg,false};
                                    M5Cardputer.Display.fillRect(0,rowY(tcy),(tcx+1)*cw(),lh(),curBg);
                                } else {
                                    for(int x=0;x<tCols;x++) activeBuf()[tcy][x]={0,curFg,curBg,false};
                                    M5Cardputer.Display.fillRect(0,rowY(tcy),DW,lh(),curBg);
                                }
                                break;
                            }
                            case 'L': { scrollRegionDown(P1(1), tcy); break; }
                            case 'M': { scrollRegionUp(P1(1), tcy);  break; }
                            case 'P': {
                                int del=P1(1);
                                for(int x=tcx;x<tCols;x++)
                                    activeBuf()[tcy][x]=(x+del<tCols)?activeBuf()[tcy][x+del]:TCell{0,curFg,curBg,false};
                                drawRow(tcy);
                                break;
                            }
                            case '@': {
                                int ins=P1(1);
                                for(int x=tCols-1;x>=tcx;x--)
                                    activeBuf()[tcy][x]=(x-ins>=tcx)?activeBuf()[tcy][x-ins]:TCell{0,curFg,curBg,false};
                                drawRow(tcy);
                                break;
                            }
                            case 'S': { scrollRegionUp(P1(1));   break; }
                            case 'T': { scrollRegionDown(P1(1)); break; }
                            case 'r': {
                                scrollTop = P1(1)-1; scrollBot = P2(tRows)-1;
                                if(scrollTop<0) scrollTop=0;
                                if(scrollBot>=tRows) scrollBot=tRows-1;
                                if(scrollTop>=scrollBot) { scrollTop=0; scrollBot=tRows-1; }
                                tcx=tcy=0;
                                break;
                            }
                            case 's': { savedCx=tcx; savedCy=tcy; break; }
                            case 'u': {
                                tcx=savedCx; tcy=savedCy;
                                if(tcx>=tCols)tcx=tCols-1;
                                if(tcy>=tRows)tcy=tRows-1;
                                break;
                            }
                            case 'm': {
                                if (pc == 0) { curFg=C_FG; curBg=C_BG; curBold=false; break; }
                                for (int pi = 0; pi < pc; pi++) {
                                    int v = (p[pi]<0)?0:p[pi];
                                    if (v==0)  { curFg=C_FG; curBg=C_BG; curBold=false; }
                                    else if (v==1)  curBold=true;
                                    else if (v==22) curBold=false;
                                    else if (v==7)  { uint16_t t=curFg; curFg=curBg; curBg=t; }
                                    else if (v==27) { curFg=C_FG; curBg=C_BG; }
                                    else if (v>=30 && v<=37) curFg=ansiCol[v-30+(curBold?8:0)];
                                    else if (v==39) curFg=C_FG;
                                    else if (v>=40 && v<=47) curBg=ansiCol[v-40];
                                    else if (v==49) curBg=C_BG;
                                    else if (v>=90 && v<=97) curFg=ansiCol[v-90+8];
                                    else if (v>=100&&v<=107) curBg=ansiCol[v-100+8];
                                }
                                M5Cardputer.Display.setTextColor(curFg, curBg);
                                break;
                            }
                            default: break;
                        }
                        csiLen = 0;
                    } else {
                        if (c2 == '?') { csiPriv = true; }
                        else if (csiLen < (int)sizeof(csiBuf)-1) csiBuf[csiLen++] = c2;
                    }
                    continue;
                }

                if (inEsc) {
                    inEsc = false;
                    if      (c2 == '[') { inCSI=true; csiLen=0; csiPriv=false; }
                    else if (c2 == ']') { inOSC=true; }
                    else if (c2 == '7') { savedCx=tcx; savedCy=tcy; }
                    else if (c2 == '8') {
                        tcx=savedCx; tcy=savedCy;
                        if(tcx>=tCols)tcx=tCols-1;
                        if(tcy>=tRows)tcy=tRows-1;
                    }
                    else if (c2 == 'M') {
                        if (tcy > scrollTop) tcy--;
                        else scrollRegionDown(1);
                    }
                    continue;
                }

                if (c2 == 0x1B) { inEsc=true; continue; }

                if (c2 == '\r') { tcx=0; continue; }
                if (c2 == '\n' || c2 == 0x0B || c2 == 0x0C) {
                    tcy++;
                    if (tcy > scrollBot) { scrollRegionUp(1); tcy=scrollBot; }
                    continue;
                }
                if (c2 == 0x08) {
                    if(tcx>0){tcx--; activeBuf()[tcy][tcx]={0,curFg,curBg,false};
                    M5Cardputer.Display.fillRect(tcx*cw(),rowY(tcy),cw(),lh(),curBg);}
                    continue;
                }
                if (c2 == 0x7F) {
                    if(tcx>0){tcx--; activeBuf()[tcy][tcx]={0,curFg,curBg,false};
                    M5Cardputer.Display.fillRect(tcx*cw(),rowY(tcy),cw(),lh(),curBg);}
                    continue;
                }
                if (c2 == '\t') {
                    int next = ((tcx/8)+1)*8;
                    while(tcx < next && tcx < tCols) putChar(' ');
                    continue;
                }
                if (c2 < 0x20) continue;

                // UTF-8: absorb continuation bytes, map box-drawing to ASCII
                if (c2 >= 0xC0) {
                    uint8_t seq[4] = {c2, 0, 0, 0};
                    int slen = 1;
                    while (slen < 4 && (i+1) < n && (uint8_t)rbuf[i+1] >= 0x80 && (uint8_t)rbuf[i+1] < 0xC0)
                        seq[slen++] = (uint8_t)rbuf[++i];

                    uint32_t cp = 0;
                    if      ((seq[0] & 0xE0) == 0xC0) cp = ((seq[0]&0x1F)<<6)  | (seq[1]&0x3F);
                    else if ((seq[0] & 0xF0) == 0xE0) cp = ((seq[0]&0x0F)<<12) | ((seq[1]&0x3F)<<6) | (seq[2]&0x3F);
                    else if ((seq[0] & 0xF8) == 0xF0) cp = ((seq[0]&0x07)<<18) | ((seq[1]&0x3F)<<12) | ((seq[2]&0x3F)<<6) | (seq[3]&0x3F);

                    char mapped = '?';
                    if      (cp == 0x00A0) mapped = ' ';
                    else if (cp >= 0x2500 && cp <= 0x2501) mapped = '-';
                    else if (cp == 0x2502 || cp == 0x2503) mapped = '|';
                    else if (cp >= 0x2504 && cp <= 0x250F) mapped = '-';
                    else if (cp >= 0x2510 && cp <= 0x2517) mapped = '+';
                    else if (cp >= 0x2518 && cp <= 0x251F) mapped = '+';
                    else if (cp >= 0x2520 && cp <= 0x252F) mapped = '+';
                    else if (cp >= 0x2530 && cp <= 0x253F) mapped = '+';
                    else if (cp >= 0x2540 && cp <= 0x254F) mapped = '+';
                    else if (cp >= 0x2550 && cp <= 0x2551) mapped = (cp==0x2551)?'|':'-';
                    else if (cp >= 0x2552 && cp <= 0x256C) mapped = '+';
                    else if (cp >= 0x2574 && cp <= 0x257F) mapped = '+';
                    else if (cp >= 0x2580 && cp <= 0x259F) mapped = '#';
                    else if (cp == 0x2190) mapped = '<';
                    else if (cp == 0x2192) mapped = '>';
                    else if (cp == 0x2191) mapped = '^';
                    else if (cp == 0x2193) mapped = 'v';
                    else if (cp == 0x2022 || cp == 0x25CF) mapped = '*';
                    else if (cp == 0x2026) mapped = '.';
                    else if (cp == 0x00B7) mapped = '.';
                    else if (cp >= 0x2018 && cp <= 0x201F) mapped = '"';
                    else if (cp >= 0x20 && cp <= 0xFF) mapped = (char)cp;

                    if (mapped != '?') putChar(mapped);
                    continue;
                }
                if (c2 >= 0x80) continue;

                putChar((char)c2);
            }
        }
        if (n < 0 || ssh_channel_is_closed(ch)) break;
    }
    done:;
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SETUP / LOOP
// ═══════════════════════════════════════════════════════════════════════════════

void setup() {
    auto cfg=M5.config();
    M5Cardputer.begin(cfg,true);
    M5Cardputer.Display.setRotation(1);
    M5Cardputer.Display.fillScreen(C_BG);
    M5Cardputer.Display.setBrightness(128);
    Serial.begin(115200);

    M5Cardputer.Display.setTextSize(2);
    M5Cardputer.Display.setTextColor(C_TITFG,C_BG);
    M5Cardputer.Display.setCursor(44,40); M5Cardputer.Display.print("SSH Client");
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextColor(C_DIM,C_BG);
    M5Cardputer.Display.setCursor(70,64); M5Cardputer.Display.print("Cardputer-Adv");
    delay(400);

    bool sdOk=SD.begin(M5.getPin(m5::pin_name_t::sd_spi_ss));
    if (sdOk) {
        if (!SD.exists("/SSHAdv"))    SD.mkdir("/SSHAdv");
        if (!SD.exists(P_WG))        SD.mkdir(P_WG);
        loadProfiles();
        loadUsers();
        loadSettings();
        if (g_cfg.autoConnect && loadWifi()) {
            M5Cardputer.Display.setTextSize(1);
            M5Cardputer.Display.setTextColor(C_DIM,C_BG);
            M5Cardputer.Display.setCursor(4,90);
            M5Cardputer.Display.printf("WiFi: %s ",g_ssid);
            WiFi.begin(g_ssid,g_wpass);
            for (int i=0;i<20&&WiFi.status()!=WL_CONNECTED;i++) {
                vTaskDelay(300/portTICK_PERIOD_MS);
                M5Cardputer.Display.print('.');
            }
            g_wifiOk=(WiFi.status()==WL_CONNECTED);
            if (g_wifiOk) M5Cardputer.Display.print(" OK");
        }
    } else {
        M5Cardputer.Display.setTextSize(1);
        M5Cardputer.Display.setTextColor(C_ERR,C_BG);
        M5Cardputer.Display.setCursor(4,90);
        M5Cardputer.Display.print("SD mount failed!");
        delay(2000);
    }

    touchActivity();
    delay(300);

    // Auto-connect after WG config switch restart
    if (g_bootProfileIdx >= 0) {
        int autoIdx = g_bootProfileIdx;
        g_bootProfileIdx = -1;
        if (autoIdx < g_profCnt && g_wifiOk) {
            bprint("Resuming...", C_DIM);
            delay(300);
            runConnect(autoIdx);
        }
    }

    runHome();
}

void loop() { vTaskDelay(50/portTICK_PERIOD_MS); }
