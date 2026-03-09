/*
 * SSH Client  –  M5Cardputer / M5Cardputer-Adv
 * ─────────────────────────────────────────────
 * Libraries (Arduino IDE):
 *   Board manager 2.x  (NOT 3.x – WireGuard compat)
 *   M5Cardputer  >= 1.1.1
 *   M5Unified    >= 0.2.8
 *   M5GFX        >= 0.2.10
 *   WireGuard-ESP32-Arduino  (ZIP install)
 *   LibSSH-ESP32             (ZIP install)
 *
 * SD layout:
 *   /profiles/wifi.cfg      – saved WiFi
 *   /profiles/users.cfg     – remembered SSH usernames
 *   /profiles/<name>.prof   – SSH profiles
 *   /profiles/wg/<x>.conf   – WireGuard configs
 *
 * Navigation everywhere:
 *   ;  = Up        .  = Down
 *   ,  = Back/Left /  = Forward/Right
 *   Enter = Select/Confirm
 *   Esc   = Back/Cancel
 *
 * SSH terminal:
 *   All keys type normally
 *   ;  .  ,  /  send ANSI arrow sequences
 *   Esc sends ESC to remote
 *   Fn+X = Ctrl-D (logout)   Fn+C = Ctrl-C
 *   Fn+Z = Ctrl-Z            Fn+L = Ctrl-L
 */

#include <WiFi.h>
#include <M5Cardputer.h>
#include <WireGuard-ESP32.h>
#include <SD.h>
#include <FS.h>
#include "libssh_esp32.h"
#include <libssh/libssh.h>

// ── Display ────────────────────────────────────────────────────────────────────
#define DW       240
#define DH       135
#define TITLEH   20
#define HINTH    12
#define BODYY    (TITLEH + 2)
#define BODYH    (DH - TITLEH - HINTH - 4)
#define LH       18    // line height, text size 2
#define LHS      10    // line height, text size 1

// ── Colours ───────────────────────────────────────────────────────────────────
#define C_BG     TFT_BLACK
#define C_FG     TFT_WHITE
#define C_DIM    0x4228u
#define C_SELBG  0x0338u
#define C_SELFG  TFT_WHITE
#define C_TITBG  0x000Bu
#define C_TITFG  0x07FFu   // cyan
#define C_HNTBG  0x1082u
#define C_HNTFG  0x7BCFu
#define C_OK     0x07E0u   // green
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

// ── Nav key codes (physical arrow/esc keys on Cardputer-Adv) ──────────────────
#define KUP    ';'
#define KDOWN  '.'
#define KLEFT  ','
#define KRIGHT '/'
#define KESC   '\x1b'
#define KENTER '\r'
#define KDEL   '\x08'

// ── Type forward declarations (required for Arduino 3.x preprocessor) ──────────
struct Profile;
struct LItem;

// ── Profile ────────────────────────────────────────────────────────────────────
struct Profile {
    char name[32];
    char host[64];
    char user[32];
    char pass[64];
    int  port;
    bool useWG;
    char wg_conffile[40];
    char wg_privkey[50];   // WG base64 key = 44 chars + null
    char wg_addr[24];
    char wg_pubkey[50];
    char wg_endpoint[48];
};

struct LItem {
    char    label[44];
    char    sub[28];    // right-aligned dim subtext
    uint16_t lc;        // label colour
    uint16_t dot;       // 0 = no dot
};

// ── Globals ────────────────────────────────────────────────────────────────────
Profile       g_prof[MAX_PROF];
int           g_profCnt   = 0;
int           g_profSel   = 0;

static WireGuard g_wg;
bool          g_wgActive  = false;

char          g_ssid[64]  = "";
char          g_wpass[64] = "";
bool          g_wifiOk    = false;

char          g_users[MAX_USR][32];
int           g_userCnt   = 0;

int           g_termY     = 0;
unsigned long g_lastKey   = 0;
#define DEBOUNCE_MS 130

const char* P_WIFI  = "/profiles/wifi.cfg";
const char* P_USERS = "/profiles/users.cfg";
const char* P_WG    = "/profiles/wg";

// ── Forward declarations ───────────────────────────────────────────────────────
void runHome();
void runWifiMenu();
void runProfileList();
void runConnect(int idx);
void runSSHTerm(ssh_session sess, ssh_channel ch, const char* title);
void editProfile(int idx);   // idx<0 = new


// ═══════════════════════════════════════════════════════════════════════════════
//  INPUT HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

inline bool isFn(const Keyboard_Class::KeysState& s) {
    return (s.modifiers & 0x10) != 0;
}

// Block until a key event; return KeysState
Keyboard_Class::KeysState waitKS() {
    while (true) {
        vTaskDelay(10 / portTICK_PERIOD_MS);
        M5Cardputer.update();
        if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed())
            return M5Cardputer.Keyboard.keysState();
    }
}

// Block until a key; return single char
// Enter→'\r', Backspace→'\b', Esc→'\x1b', other chars as-is
char waitCh() {
    while (true) {
        auto st = waitKS();
        if (st.enter) return '\r';
        if (st.del)   return '\b';
        for (auto c : st.word) return c;
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
    // WiFi indicator top-right
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
    g_termY = BODYY;
}

// Print one line in body, auto-scroll at bottom
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
    g_termY = M5Cardputer.Display.getCursorY();
}

void bprintf(uint16_t col, const char* fmt, ...) {
    char buf[128]; va_list a; va_start(a, fmt);
    vsnprintf(buf, sizeof(buf), fmt, a); va_end(a);
    bprint(buf, col);
}


// ═══════════════════════════════════════════════════════════════════════════════
//  GENERIC SCROLLABLE LIST
//  Returns selected index or -1 (Esc/Left = cancel)
// ═══════════════════════════════════════════════════════════════════════════════

int visRows() { return BODYH / LH; }

void drawList(const LItem* it, int cnt, int sel, int sc,
                     const char* title, const char* hint) {
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
        int y   = BODYY + i * LH;
        bool hi = (idx == sel);
        uint16_t bg = hi ? C_SELBG : C_BG;
        if (hi) M5Cardputer.Display.fillRect(0, y, DW, LH, C_SELBG);

        // dot badge
        if (it[idx].dot)
            M5Cardputer.Display.fillCircle(5, y + LH/2, 3, it[idx].dot);

        // label
        M5Cardputer.Display.setTextSize(2);
        M5Cardputer.Display.setTextColor(hi ? C_SELFG : it[idx].lc, bg);
        M5Cardputer.Display.setCursor(13, y + 1);
        M5Cardputer.Display.print(it[idx].label);

        // sub (small, right-aligned)
        if (it[idx].sub[0]) {
            int sw = strlen(it[idx].sub) * 6;
            M5Cardputer.Display.setTextSize(1);
            M5Cardputer.Display.setTextColor(C_DIM, bg);
            M5Cardputer.Display.setCursor(DW - sw - 3, y + 5);
            M5Cardputer.Display.print(it[idx].sub);
        }
    }
}

// Full interactive list; startSel = initial selection
int runList(LItem* it, int cnt, const char* title, const char* hint,
            int startSel = 0) {
    int rows = visRows();
    int sel  = (startSel < cnt) ? startSel : 0;
    int sc   = (sel >= rows) ? sel - rows + 1 : 0;

    drawList(it, cnt, sel, sc, title, hint);

    while (true) {
        char c = waitCh();
        if (c == KUP) {
            if (sel > 0) { sel--; if (sel < sc) sc = sel; drawList(it,cnt,sel,sc,title,hint); }
        } else if (c == KDOWN) {
            if (sel < cnt-1) { sel++; if (sel >= sc+rows) sc = sel-rows+1; drawList(it,cnt,sel,sc,title,hint); }
        } else if (c == '\r' || c == KRIGHT) {
            return cnt > 0 ? sel : -1;
        } else if (c == KESC || c == KLEFT) {
            return -1;
        }
    }
}

// Convenience: build a list from a plain string array
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
    return runList(items, lim, title, ";.=nav  Enter=pick  Esc=back", startSel);
}


// ═══════════════════════════════════════════════════════════════════════════════
//  YES / NO DIALOG  –  no typing, arrows to choose
// ═══════════════════════════════════════════════════════════════════════════════

bool yesNo(const char* title, const char* q, bool defYes = false) {
    int sel = defYes ? 0 : 1;

    auto draw = [&]() {
        screenInit(title, "  ,/= toggle    Enter=confirm");
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
        if (c == KLEFT  || c == KUP   || c == KRIGHT || c == KDOWN)
            { sel = 1 - sel; draw(); }
        if (c == '\r') return sel == 0;
        if (c == KESC) return false;
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  TEXT INPUT  –  only used when no list alternative exists
// ═══════════════════════════════════════════════════════════════════════════════

String typeText(const char* title, const char* prompt,
                const char* prefill = "", bool hidden = false) {
    screenInit(title, "Enter=done  Bksp=del  Esc=accept");
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
        if (hidden) for (size_t i = 0; i < val.length(); i++) M5Cardputer.Display.print('*');
        else        M5Cardputer.Display.print(val);
        // cursor indicator
        M5Cardputer.Display.fillRect(M5Cardputer.Display.getCursorX(), iy, 8, LH, C_TITFG);
    };
    redraw();

    while (true) {
        vTaskDelay(10 / portTICK_PERIOD_MS);
        M5Cardputer.update();
        if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed()) continue;
        auto st = M5Cardputer.Keyboard.keysState();

        if (st.enter) return val;
        if (st.del && val.length()) { val.remove(val.length()-1); redraw(); continue; }
        if (!isFn(st)) {
            for (auto ch : st.word) {
                if (ch == KESC)   return val;
                // Don't let nav keys pollute text
                if (ch == KUP || ch == KDOWN || ch == KLEFT || ch == KRIGHT) continue;
                val += ch;
            }
            redraw();
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  FILE I/O
// ═══════════════════════════════════════════════════════════════════════════════

String profPath(const char* n) { return String("/profiles/") + n + ".prof"; }

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
    File dir = SD.open("/profiles");
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
             p.name,p.host,p.user,p.pass,p.port);
    f.printf("wg=%d\nwg_conffile=%s\nwg_privkey=%s\nwg_addr=%s\nwg_pubkey=%s\nwg_endpoint=%s\n",
             p.useWG?1:0,p.wg_conffile,p.wg_privkey,p.wg_addr,p.wg_pubkey,p.wg_endpoint);
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

// Returns true = file picked+parsed, false = manual entry wanted
bool pickWGConf(Profile& p) {
    static char   names[MAX_WGF][40];
    static const char* ptrs[MAX_WGF+1];
    int n = 0;
    File dir = SD.open(P_WG);
    if (dir && dir.isDirectory()) {
        File e;
        while ((e = dir.openNextFile()) && n < MAX_WGF) {
            String fn = e.name();
            if (fn.endsWith(".conf")) { strncpy(names[n], fn.c_str(), 39); ptrs[n]=names[n]; n++; }
            e.close();
        }
        dir.close();
    }
    ptrs[n] = "Enter keys manually";
    int ch = pickStr(ptrs, n+1, "WireGuard config");
    if (ch < 0 || ch == n) return false;
    screenInit("Loading WG", "");
    bprintf(C_DIM, "%s", names[ch]);
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
//  PROFILE DETAIL CARD  –  shown before connecting
// ═══════════════════════════════════════════════════════════════════════════════

void profileCard(const Profile& p) {
    screenInit(p.name, "Enter=connect  E=edit  Esc=back");
    // Draw a card in the body
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
    row("Pass:  ", p.pass[0] ? "••••••" : "(none)", C_DIM);
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
    if (isNew) { memset(&p,0,sizeof(p)); p.port=22; }
    else        p = g_prof[idx];

    // ── Name ──
    { String v = typeText(isNew?"New Profile":"Edit Profile", "Profile name:", p.name);
      if (v.isEmpty() && isNew) return;
      strncpy(p.name, v.c_str(), sizeof(p.name)-1); }

    // ── Host ──
    { String v = typeText(p.name, "Host / IP:", p.host);
      strncpy(p.host, v.c_str(), sizeof(p.host)-1); }

    // ── Port: pick from list ──
    { const char* po[] = { "22   (SSH default)", "2222", "Custom..." };
      int cur = (p.port==22)?0:(p.port==2222)?1:2;
      int ch = pickStr(po, 3, "SSH Port", cur);
      if      (ch == 0) p.port = 22;
      else if (ch == 1) p.port = 2222;
      else if (ch == 2) {
          char buf[8]; snprintf(buf,sizeof(buf),"%d",p.port);
          String v = typeText(p.name,"Port number:",buf);
          int pv = v.toInt(); p.port = (pv>0)?pv:22;
      }
      // ch==-1 (Esc) → keep existing port
    }

    // ── User: pick remembered or type new ──
    {
        static const char* uo[MAX_USR+2];
        int n = 0;
        if (p.user[0]) uo[n++] = p.user;   // current first
        for (int i=0; i<g_userCnt; i++) {
            bool dup = p.user[0] && strcmp(g_users[i],p.user)==0;
            if (!dup) uo[n++] = g_users[i];
        }
        uo[n] = "Type new username...";
        int ch = pickStr(uo, n+1, "SSH User");
        if      (ch >= 0 && ch < n)  strncpy(p.user, uo[ch], sizeof(p.user)-1);
        else if (ch == n) {
            String v = typeText(p.name,"SSH username:",p.user);
            strncpy(p.user,v.c_str(),sizeof(p.user)-1);
            addUser(p.user);
        }
        // ch==-1 → keep existing
    }

    // ── Password: change or keep ──
    { const char* po[] = { "Keep existing password", "Change password" };
      int cur = p.pass[0] ? 0 : 1;
      int ch = pickStr(po, 2, "SSH Password", cur);
      if (ch == 1) {
          String v = typeText(p.name,"New password:","",true);
          strncpy(p.pass,v.c_str(),sizeof(p.pass)-1);
      }
    }

    // ── WireGuard: on/off ──
    { const char* wo[] = { "No WireGuard", "Use WireGuard" };
      int ch = pickStr(wo, 2, "WireGuard", p.useWG?1:0);
      if (ch >= 0) p.useWG = (ch==1);
    }

    // ── If WG on: pick file or manual ──
    if (p.useWG) {
        bool fromFile = pickWGConf(p);
        if (!fromFile) {
            bool reenter = true;
            if (p.wg_privkey[0])
                reenter = yesNo("WireGuard Keys","Replace existing keys?",false);
            if (reenter) {
                p.wg_privkey[0]=p.wg_addr[0]=p.wg_pubkey[0]=p.wg_endpoint[0]=p.wg_conffile[0]='\0';
                { String v=typeText("WG: Private key","Private key:",p.wg_privkey);
                  strncpy(p.wg_privkey,v.c_str(),sizeof(p.wg_privkey)-1); }
                { String v=typeText("WG: Tunnel IP","IP/prefix (e.g. 10.0.0.2/24):",p.wg_addr);
                  strncpy(p.wg_addr,v.c_str(),sizeof(p.wg_addr)-1); }
                { String v=typeText("WG: Peer pubkey","Peer public key:",p.wg_pubkey);
                  strncpy(p.wg_pubkey,v.c_str(),sizeof(p.wg_pubkey)-1); }
                { String v=typeText("WG: Endpoint","host:port:",p.wg_endpoint);
                  strncpy(p.wg_endpoint,v.c_str(),sizeof(p.wg_endpoint)-1); }
            }
        }
    }

    // ── Save? ──
    if (yesNo(p.name,"Save profile?",true)) {
        // If renamed, remove old file
        if (!isNew && strcmp(g_prof[idx].name,p.name)!=0)
            SD.remove(profPath(g_prof[idx].name).c_str());
        saveProf(p);
        if (isNew) {
            if (g_profCnt < MAX_PROF) { g_prof[g_profCnt++]=p; g_profSel=g_profCnt-1; }
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
    int rows  = visRows();
    int sc    = (g_profSel >= rows) ? g_profSel - rows + 1 : 0;
    static LItem items[MAX_PROF];

    auto build = [&]() {
        for (int i=0; i<g_profCnt; i++) {
            strncpy(items[i].label, g_prof[i].name, sizeof(items[i].label)-1);
            items[i].label[sizeof(items[i].label)-1]='\0';
            // sub = "user@host:port"
            snprintf(items[i].sub, sizeof(items[i].sub), "%s:%d", g_prof[i].host, g_prof[i].port);
            items[i].lc  = C_FG;
            items[i].dot = g_prof[i].useWG ? C_WARN : C_OK;
        }
    };

    while (true) {
        build();
        drawList(items, g_profCnt, g_profSel, sc,
                 "Profiles",
                 ";.=nav  Ent=open  N=new  E=edit  D=del");

        char c = waitCh();

        if (c == KUP) {
            if (g_profSel > 0) {
                g_profSel--;
                if (g_profSel < sc) sc = g_profSel;
                build(); drawList(items,g_profCnt,g_profSel,sc,"Profiles",";.=nav  Ent=open  N=new  E=edit  D=del");
            }
        } else if (c == KDOWN) {
            if (g_profSel < g_profCnt-1) {
                g_profSel++;
                if (g_profSel >= sc+rows) sc = g_profSel-rows+1;
                build(); drawList(items,g_profCnt,g_profSel,sc,"Profiles",";.=nav  Ent=open  N=new  E=edit  D=del");
            }
        } else if (c == '\r' || c == KRIGHT) {
            if (g_profCnt == 0) continue;
            // Show detail card; wait for action
            profileCard(g_prof[g_profSel]);
            char c2 = waitCh();
            if (c2 == '\r' || c2 == KRIGHT) {
                runConnect(g_profSel);
            } else if (c2 == 'e' || c2 == 'E') {
                editProfile(g_profSel);
            }
            // recalc scroll
            sc = (g_profSel >= rows) ? g_profSel - rows + 1 : 0;
        } else if (c == 'n' || c == 'N') {
            editProfile(-1);
            sc = (g_profSel >= rows) ? g_profSel - rows + 1 : 0;
        } else if (c == 'e' || c == 'E') {
            if (g_profCnt > 0) {
                editProfile(g_profSel);
                sc = (g_profSel >= rows) ? g_profSel - rows + 1 : 0;
            }
        } else if (c == 'd' || c == 'D') {
            if (g_profCnt > 0) {
                char q[48]; snprintf(q,sizeof(q),"Delete '%s'?",g_prof[g_profSel].name);
                if (yesNo("Delete",q,false)) {
                    deleteProf(g_profSel);
                    sc = (g_profSel >= rows) ? g_profSel - rows + 1 : 0;
                }
            }
        } else if (c == KESC || c == KLEFT) {
            return;
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  WIFI
// ═══════════════════════════════════════════════════════════════════════════════

void doConnect(const String& ssid, const String& pw) {
    screenInit("WiFi","");
    bprintf(C_DIM,"Connecting: %s", ssid.c_str());
    WiFi.begin(ssid.c_str(), pw.c_str());
    for (int i=0; i<30 && WiFi.status()!=WL_CONNECTED; i++) {
        vTaskDelay(400/portTICK_PERIOD_MS);
        M5Cardputer.Display.print('.');
    }
    M5Cardputer.Display.println();
    if (WiFi.status()==WL_CONNECTED) {
        g_wifiOk=true;
        strncpy(g_ssid, ssid.c_str(), sizeof(g_ssid)-1);
        strncpy(g_wpass, pw.c_str(), sizeof(g_wpass)-1);
        bprint("Connected!", C_OK);
        delay(400);
        if (yesNo("WiFi","Save credentials?",true)) saveWifi();
    } else {
        bprint("Failed.", C_ERR); delay(1200);
    }
}

void runWifiScan() {
    screenInit("Scanning",""); bprint("Please wait...",C_DIM);
    int found = WiFi.scanNetworks();
    if (found <= 0) { bprint("Nothing found.",C_ERR); delay(1200); return; }
    if (found > MAX_NET) found = MAX_NET;
    static LItem items[MAX_NET];
    for (int i=0; i<found; i++) {
        strncpy(items[i].label, WiFi.SSID(i).c_str(), sizeof(items[i].label)-1);
        items[i].label[sizeof(items[i].label)-1]='\0';
        snprintf(items[i].sub,sizeof(items[i].sub),"%ddBm",WiFi.RSSI(i));
        items[i].lc  = C_FG;
        items[i].dot = (WiFi.encryptionType(i)==WIFI_AUTH_OPEN) ? C_OK : C_WARN;
    }
    int ch = runList(items,found,"Select Network",";.=nav  Enter=connect  Esc=back");
    if (ch < 0) return;
    String ssid = WiFi.SSID(ch);
    String pw   = "";
    if (WiFi.encryptionType(ch) != WIFI_AUTH_OPEN)
        pw = typeText("WiFi Password", ssid.c_str(), "", true);
    doConnect(ssid, pw);
}

void runWifiMenu() {
    while (true) {
        static char item0[56];
        snprintf(item0,sizeof(item0), g_wifiOk ? "Scan  (now: %s)" : "Scan networks", g_ssid);
        const char* opts[4]; int n=0;
        opts[n++] = item0;
        opts[n++] = "Enter SSID manually";
        if (g_wifiOk) opts[n++] = "Disconnect";
        opts[n++] = "Back";
        int ch = pickStr(opts, n, "WiFi");
        if (ch < 0) return;
        const char* sel = opts[ch];
        if      (strcmp(sel,"Back")==0)          return;
        else if (strncmp(sel,"Scan",4)==0)        runWifiScan();
        else if (strcmp(sel,"Enter SSID manually")==0) {
            String ssid = typeText("WiFi Manual","SSID:");
            String pw   = typeText("WiFi Manual","Password:","",true);
            doConnect(ssid, pw);
        } else if (strcmp(sel,"Disconnect")==0) {
            WiFi.disconnect(true); g_wifiOk=false;
            screenInit("WiFi",""); bprint("Disconnected.",C_DIM); delay(800);
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  HOME SCREEN  –  3 icon tiles, left/right to pick
// ═══════════════════════════════════════════════════════════════════════════════

void drawHomeTile(int x, int w, int idx, bool hi) {
    uint16_t bg  = hi ? C_SELBG : C_BG;
    uint16_t col = hi ? (uint16_t[]){C_WIFI,C_PROF,C_SETT}[idx]
                      : C_DIM;
    if (hi) M5Cardputer.Display.fillRoundRect(x+1,2,w-2,DH-HINTH-4,5,C_SELBG);

    int cx = x + w/2;
    int iy = 28;

    if (idx == 0) {
        // WiFi arcs
        M5Cardputer.Display.fillCircle(cx, iy+22, 3, col);
        { const int wrs[]={8,14,20}; for(int i=0;i<3;i++) M5Cardputer.Display.drawCircle(cx, iy+22, wrs[i], col); }  // full circles look ok small
    } else if (idx == 1) {
        // Terminal box
        M5Cardputer.Display.drawRoundRect(cx-18,iy,36,22,3,col);
        M5Cardputer.Display.setTextSize(1);
        M5Cardputer.Display.setTextColor(col,bg);
        M5Cardputer.Display.setCursor(cx-14,iy+4);  M5Cardputer.Display.print(">_");
        M5Cardputer.Display.setCursor(cx-12,iy+13); M5Cardputer.Display.print("ssh");
    } else {
        // Gear (simple cross)
        M5Cardputer.Display.drawCircle(cx,iy+11,9,col);
        M5Cardputer.Display.drawLine(cx,iy,   cx,iy+2,col);
        M5Cardputer.Display.drawLine(cx,iy+20,cx,iy+22,col);
        M5Cardputer.Display.drawLine(cx-11,iy+11,cx-9,iy+11,col);
        M5Cardputer.Display.drawLine(cx+9, iy+11,cx+11,iy+11,col);
        M5Cardputer.Display.drawCircle(cx,iy+11,4,col);
    }

    const char* labels[] = {"WiFi","Profiles","Settings"};
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextColor(hi?C_FG:C_DIM, bg);
    int lx = cx - strlen(labels[idx])*3;
    M5Cardputer.Display.setCursor(lx, iy+26);
    M5Cardputer.Display.print(labels[idx]);
}

void drawHome(int sel) {
    M5Cardputer.Display.fillScreen(C_BG);
    int w = DW / 3;
    for (int i=0; i<3; i++) drawHomeTile(w*i, w, i, i==sel);

    // bottom status bar
    char hbuf[64];
    if (g_wifiOk) snprintf(hbuf,sizeof(hbuf),"  WiFi: %s",g_ssid);
    else          snprintf(hbuf,sizeof(hbuf),"  ,/=nav  Enter=open  No WiFi");
    hintBar(hbuf);
}

void runHome() {
    int sel = 0;
    while (true) {
        drawHome(sel);
        char c = waitCh();
        if (c==KLEFT  || c==KUP)   { if (sel>0)   { sel--; } }
        if (c==KRIGHT || c==KDOWN) { if (sel<2)    { sel++; } }
        if (c=='\r') {
            if (sel==0) runWifiMenu();
            if (sel==1) runProfileList();
            if (sel==2) {
                screenInit("Settings","Esc=back");
                bprint("Coming soon.",C_DIM);
                while (waitCh()!=KESC) {}
            }
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  CONNECT  (WireGuard + SSH)
// ═══════════════════════════════════════════════════════════════════════════════

void runConnect(int idx) {
    const Profile& p = g_prof[idx];
    screenInit(p.name,"");

    if (p.useWG) {
        if (g_wgActive) { bprint("Stopping WG…",C_DIM); g_wgActive=false; }
        bprint("WireGuard…",C_DIM);
        IPAddress tun;
        String a = p.wg_addr; int sl=a.indexOf('/'); if(sl>=0) a=a.substring(0,sl);
        if (!tun.fromString(a)) { bprint("Bad WG IP!",C_ERR); delay(2000); return; }
        String ep = p.wg_endpoint;
        int co = ep.lastIndexOf(':');
        if (co<0) { bprint("Bad WG endpoint!",C_ERR); delay(2000); return; }
        configTime(0,0,"pool.ntp.org","time.google.com"); delay(800);
        g_wg.begin(tun, p.wg_privkey, ep.substring(0,co).c_str(),
                   p.wg_pubkey, ep.substring(co+1).toInt());
        g_wgActive=true;
        bprint("WG up.",C_OK);
    }

    bprint("SSH connecting…",C_DIM);
    ssh_session sess = ssh_new();
    if (!sess) { bprint("SSH alloc failed",C_ERR); delay(2000); goto cleanup; }

    {
        int verb=SSH_LOG_NOLOG, port=p.port;
        ssh_options_set(sess,SSH_OPTIONS_HOST,p.host);
        ssh_options_set(sess,SSH_OPTIONS_USER,p.user);
        ssh_options_set(sess,SSH_OPTIONS_PORT,&port);
        ssh_options_set(sess,SSH_OPTIONS_LOG_VERBOSITY,&verb);

        if (ssh_connect(sess)!=SSH_OK) {
            bprintf(C_ERR,"Conn: %s",ssh_get_error(sess));
            delay(2000); ssh_free(sess); sess=nullptr; goto cleanup;
        }
        if (ssh_userauth_password(sess,nullptr,p.pass)!=SSH_AUTH_SUCCESS) {
            bprint("Auth failed.",C_ERR);
            delay(2000); ssh_disconnect(sess); ssh_free(sess); sess=nullptr; goto cleanup;
        }
        ssh_channel ch = ssh_channel_new(sess);
        if (!ch || ssh_channel_open_session(ch)!=SSH_OK ||
            ssh_channel_request_pty(ch)!=SSH_OK ||
            ssh_channel_request_shell(ch)!=SSH_OK) {
            bprint("Shell open failed",C_ERR);
            delay(2000); if(ch) ssh_channel_free(ch); goto cleanup;
        }

        M5Cardputer.Display.fillScreen(C_BG);
        titleBar(p.name);
        hintBar("Fn+X=quit  Fn+C=^C  ;.=arrows");
        M5Cardputer.Display.setTextSize(1);
        M5Cardputer.Display.setCursor(0,TITLEH+2);
        g_termY = TITLEH+2;

        runSSHTerm(sess, ch, p.name);

        ssh_channel_close(ch); ssh_channel_free(ch);
        ssh_disconnect(sess);  ssh_free(sess); sess=nullptr;
    }

cleanup:
    if (sess) { ssh_disconnect(sess); ssh_free(sess); }
    if (p.useWG) g_wgActive=false;
    screenInit(p.name,"Any key to return");
    bprint("Session ended.",C_DIM);
    waitCh();
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SSH TERMINAL
// ═══════════════════════════════════════════════════════════════════════════════

void runSSHTerm(ssh_session sess, ssh_channel ch, const char* /*title*/) {
    int lim = DH - HINTH - LHS;
    String line = "";

    while (true) {
        vTaskDelay(8/portTICK_PERIOD_MS);
        M5Cardputer.update();

        // Keyboard input
        if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
            unsigned long now = millis();
            if (now - g_lastKey >= DEBOUNCE_MS) {
                g_lastKey = now;
                auto st = M5Cardputer.Keyboard.keysState();
                bool fn = isFn(st);

                if (fn) {
                    for (auto c : st.word) {
                        const char* seq = nullptr;
                        char ctrl = 0;
                        switch (c|32) {   // lowercase
                            case 'x': ctrl=0x04; break;
                            case 'c': ctrl=0x03; break;
                            case 'z': ctrl=0x1A; break;
                            case 'l': ctrl=0x0C; break;
                        }
                        if (ctrl) ssh_channel_write(ch,&ctrl,1);
                    }
                } else {
                    for (auto c : st.word) {
                        // Nav keys → ANSI sequences
                        if (c==KUP)    { ssh_channel_write(ch,"\x1b[A",3); continue; }
                        if (c==KDOWN)  { ssh_channel_write(ch,"\x1b[B",3); continue; }
                        if (c==KRIGHT) { ssh_channel_write(ch,"\x1b[C",3); continue; }
                        if (c==KLEFT)  { ssh_channel_write(ch,"\x1b[D",3); continue; }
                        if (c==KESC)   { ssh_channel_write(ch,"\x1b",1);   continue; }
                        // Normal char – echo locally and add to line buffer
                        line += c;
                        M5Cardputer.Display.print(c);
                        g_termY = M5Cardputer.Display.getCursorY();
                    }
                    if (st.del && line.length()) {
                        line.remove(line.length()-1);
                        int cx = M5Cardputer.Display.getCursorX()-6;
                        int cy = M5Cardputer.Display.getCursorY();
                        M5Cardputer.Display.setCursor(cx,cy);
                        M5Cardputer.Display.print(' ');
                        M5Cardputer.Display.setCursor(cx,cy);
                    }
                    if (st.enter) {
                        line += "\r\n";
                        ssh_channel_write(ch, line.c_str(), line.length());
                        line = "";
                        M5Cardputer.Display.println();
                        g_termY = M5Cardputer.Display.getCursorY();
                    }
                }
            }
        }

        // Auto-scroll local display
        if (g_termY > lim) {
            M5Cardputer.Display.scroll(0,-LHS);
            M5Cardputer.Display.fillRect(0,lim,DW,LHS,C_BG);
            M5Cardputer.Display.setCursor(0,lim);
            g_termY = lim;
        }

        // SSH output – basic ANSI strip (ESC [ … letter)
        char rbuf[256];
        int n = ssh_channel_read_nonblocking(ch,rbuf,sizeof(rbuf),0);
        if (n > 0) {
            bool inEsc = false; bool inCSI = false;
            for (int i=0; i<n; i++) {
                uint8_t c = rbuf[i];
                if (inCSI)  { inCSI  = (c>='0'&&c<='?'); if(!inCSI&&!(c>='@'&&c<='~')) {}; continue; }
                if (inEsc)  { inEsc=false; if(c=='[') inCSI=true; continue; }
                if (c==0x1B){ inEsc=true; continue; }
                if (c=='\r') continue;
                if (g_termY > lim) {
                    M5Cardputer.Display.scroll(0,-LHS);
                    M5Cardputer.Display.fillRect(0,lim,DW,LHS,C_BG);
                    M5Cardputer.Display.setCursor(0,lim);
                    g_termY=lim;
                }
                M5Cardputer.Display.write(c);
                g_termY = M5Cardputer.Display.getCursorY();
            }
        }
        if (n<0 || ssh_channel_is_closed(ch)) break;
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SETUP / LOOP
// ═══════════════════════════════════════════════════════════════════════════════

void setup() {
    auto cfg = M5.config();
    M5Cardputer.begin(cfg,true);
    M5Cardputer.Display.setRotation(1);
    M5Cardputer.Display.fillScreen(C_BG);
    Serial.begin(115200);

    // Splash
    M5Cardputer.Display.setTextSize(2);
    M5Cardputer.Display.setTextColor(C_TITFG,C_BG);
    M5Cardputer.Display.setCursor(44,40); M5Cardputer.Display.print("SSH Client");
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextColor(C_DIM,C_BG);
    M5Cardputer.Display.setCursor(70,64); M5Cardputer.Display.print("Cardputer-Adv");
    delay(400);

    // SD
    bool sdOk = SD.begin(M5.getPin(m5::pin_name_t::sd_spi_ss));
    if (sdOk) {
        if (!SD.exists("/profiles")) SD.mkdir("/profiles");
        if (!SD.exists(P_WG))       SD.mkdir(P_WG);
        loadProfiles();
        loadUsers();
        if (loadWifi()) {
            M5Cardputer.Display.setTextSize(1);
            M5Cardputer.Display.setTextColor(C_DIM,C_BG);
            M5Cardputer.Display.setCursor(4,90);
            M5Cardputer.Display.printf("WiFi: %s ", g_ssid);
            WiFi.begin(g_ssid,g_wpass);
            for (int i=0; i<20 && WiFi.status()!=WL_CONNECTED; i++) {
                vTaskDelay(300/portTICK_PERIOD_MS);
                M5Cardputer.Display.print('.');
            }
            g_wifiOk = (WiFi.status()==WL_CONNECTED);
            if (g_wifiOk) M5Cardputer.Display.print(" OK");
        }
    } else {
        M5Cardputer.Display.setTextSize(1);
        M5Cardputer.Display.setTextColor(C_ERR,C_BG);
        M5Cardputer.Display.setCursor(4,90);
        M5Cardputer.Display.print("SD mount failed!");
        delay(2000);
    }

    delay(300);
    runHome();
}

void loop() { vTaskDelay(50/portTICK_PERIOD_MS); }
