/*
 * SSH Client  –  M5Cardputer / M5Cardputer-Adv
 * ─────────────────────────────────────────────
 * Libraries (Arduino IDE):
 *   Board manager 3.x  (with patched WireGuard-ESP32-bis ZIP)
 *   M5Cardputer  >= 1.1.1
 *   M5Unified    >= 0.2.8
 *   M5GFX        >= 0.2.10
 *   WireGuard-ESP32-bis  (ZIP from issue #45)
 *   LibSSH-ESP32         (ZIP install)
 *
 * SD layout:
 *   /SSHAdv/wifi.cfg      – saved WiFi
 *   /SSHAdv/users.cfg     – remembered SSH usernames
 *   /SSHAdv/settings.cfg  – screen/SSH/WiFi timeouts
 *   /SSHAdv/<n>.prof      – SSH profiles
 *   /SSHAdv/wg/<x>.conf   – WireGuard configs
 *
 * Navigation everywhere:
 *   ;  = Up        .  = Down
 *   ,  = Back      /  = Forward
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
#include <math.h>
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
// Physical arrow/esc keys on Cardputer-Adv
#define KUP    ';'
#define KDOWN  '.'
#define KLEFT  ','
#define KRIGHT '/'
#define KESC   '\x1b'

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
    int  passDisplay;   // 0=hide all (****), 1=show last 3, 2=show all
};

// ── Globals ────────────────────────────────────────────────────────────────────
Profile  g_prof[MAX_PROF];
int      g_profCnt  = 0;
int      g_profSel  = 0;

static WireGuard* g_wg = nullptr;
bool     g_wgActive = false;

char     g_ssid[64]  = "";
char     g_wpass[64] = "";
bool     g_wifiOk    = false;

char     g_users[MAX_USR][32];
int      g_userCnt   = 0;

Settings g_cfg = { 60, 0, 0, 128, 1, true, false, 22, true, 0 };

// SSH task context — allocated as global to avoid heap fragmentation
struct SSHTaskCtx {
    Profile      prof;
    ssh_session  sess;
    ssh_channel  ch;
    volatile int state;   // 0=running, 1=ok, 2=failed
    char         errmsg[80];
};
static SSHTaskCtx g_sshCtx;

int      g_termY     = 0;
unsigned long g_lastKey  = 0;
unsigned long g_lastAct  = 0;   // last any-key activity, for screen timeout
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

// Call this in any blocking wait loop (not SSH terminal — handled separately)
void checkScreenTimeout() {
    if (g_cfg.screenTimeoutSec <= 0 || g_dimmed) return;
    if ((millis() - g_lastAct) > (unsigned long)g_cfg.screenTimeoutSec * 1000UL) {
        M5Cardputer.Display.setBrightness(0);
        g_dimmed = true;
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  INPUT HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// Fn and Ctrl are regular keys on Cardputer, not modifier bits.
// Use isKeyPressed() to detect them. hid_keys contains raw HID scancodes.
// HID a=0x04, b=0x05 ... z=0x1D
// HID arrows: up=0x52, down=0x51, left=0x50, right=0x4F
inline bool isFn(const Keyboard_Class::KeysState& s) {
    return M5Cardputer.Keyboard.isKeyPressed(KEY_FN);
}
inline bool isCtrl(const Keyboard_Class::KeysState& s) {
    return M5Cardputer.Keyboard.isKeyPressed(KEY_LEFT_CTRL);
}
// Convert HID keycode to a-z (returns 0 if not a letter key)
inline char hidToAlpha(uint8_t hid) {
    if (hid >= 0x04 && hid <= 0x1D) return 'a' + (hid - 0x04);
    return 0;
}

// Block until a key event; also handles screen timeout polling
Keyboard_Class::KeysState waitKS() {
    while (true) {
        vTaskDelay(20 / portTICK_PERIOD_MS);
        checkScreenTimeout();
        M5Cardputer.update();
        if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
            touchActivity();
            if (g_cfg.buzzer) {
                M5Cardputer.Speaker.tone(4000, 20);  // short 20ms click at 4kHz
            }
            return M5Cardputer.Keyboard.keysState();
        }
    }
}

// Returns single char. Enter→'\r', Backspace→'\b', Esc/Back→KLEFT (',')
// NOTE: On M5Cardputer the Esc key does NOT appear in st.word (it's a raw HID
// key the library doesn't expose as a char). We therefore treat BOTH the
// physical Esc key (detected via st.fn workaround below) AND the ',' key as
// "back/cancel" — both return KLEFT so all back-checks just test for KLEFT.
// Screens show ", = back" in their hint bars.
char waitCh() {
    while (true) {
        auto st = waitKS();
        if (st.enter) return '\r';
        if (st.del)   return '\b';
        // Scan word for any char
        for (auto c : st.word) {
            // If Esc somehow appears as 0x1b, treat as back
            if ((uint8_t)c == 0x1b) return KLEFT;
            return c;
        }
        // st.word was empty — unrecognised key, loop again
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
    g_termY = BODYY;
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
    g_termY = M5Cardputer.Display.getCursorY();
}

void bprintf(uint16_t col, const char* fmt, ...) {
    char buf[128]; va_list a; va_start(a, fmt);
    vsnprintf(buf, sizeof(buf), fmt, a); va_end(a);
    bprint(buf, col);
}


// ═══════════════════════════════════════════════════════════════════════════════
//  GENERIC SCROLLABLE LIST  with marquee on selected row
// ═══════════════════════════════════════════════════════════════════════════════

int visRows() { return BODYH / LH; }

// How many chars fit in the label area at text size 2
// Label starts at x=13; sub text (if present) reserves 50px on the right
// Char width at size 2 = 12px
static int labelCols(bool hasSub) { return hasSub ? 14 : 18; }

// Draw a single list row. marqOff = char offset into label for selected row scroll.
void drawRow(const LItem& it, int y, bool hi, int marqOff) {
    uint16_t bg = hi ? C_SELBG : C_BG;
    if (hi) M5Cardputer.Display.fillRect(0, y, DW, LH, C_SELBG);
    if (it.dot)
        M5Cardputer.Display.fillCircle(5, y + LH/2, 3, it.dot);

    int maxCols = labelCols(it.sub[0] != '\0');
    int lblLen  = strlen(it.label);

    char lbuf[20];
    if (!hi || lblLen <= maxCols) {
        // Non-selected or short enough: just truncate
        strncpy(lbuf, it.label, maxCols);
        lbuf[maxCols] = '\0';
    } else {
        // Selected and too long: show scrolling window
        int off = marqOff % (lblLen + 3);  // +3 = gap before text loops
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

// Redraw only the selected row (for marquee updates — avoids full screen flicker)
void redrawSelRow(const LItem* it, int cnt, int sel, int sc,
                  const char* title, const char* hint, int marqOff) {
    int rows = visRows();
    int rowIdx = sel - sc;
    if (rowIdx < 0 || rowIdx >= rows) return;
    int lblLen = strlen(it[sel].label);
    int maxCols = labelCols(it[sel].sub[0] != '\0');
    if (lblLen <= maxCols) return;  // short enough, no need to redraw
    drawRow(it[sel], BODYY + rowIdx * LH, true, marqOff);
}

int runList(LItem* it, int cnt, const char* title, const char* hint,
            int startSel = 0) {
    int rows   = visRows();
    int sel    = (startSel < cnt) ? startSel : 0;
    int sc     = (sel >= rows) ? sel - rows + 1 : 0;
    int marqOff = 0;
    unsigned long lastMarq = millis();
    const unsigned long MARQ_MS = 220;  // scroll one char every 220ms

    drawList(it, cnt, sel, sc, title, hint, marqOff);

    while (true) {
        // Non-blocking poll for keys
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

        // Marquee tick — advance one char if selected label is long
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

// String-array list — labels truncated to 28 chars to prevent overflow
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
//  Nav keys (;  .  ,  /) are suppressed — they won't type or navigate here
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
                // show full password
                M5Cardputer.Display.print(val);
            } else if (g_cfg.passDisplay == 1) {
                // show last 3 chars
                int show = (len >= 3) ? 3 : len;
                int hide = len - show;
                for (int i = 0; i < hide; i++) M5Cardputer.Display.print('*');
                for (int i = hide; i < len; i++) M5Cardputer.Display.print(val[i]);
            } else {
                // all hidden
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

        // In text input: Fn key combos are ignored entirely (no ctrl chars)
        if (M5Cardputer.Keyboard.isKeyPressed(KEY_FN)) continue;

        for (auto ch : st.word) {
            // , = cancel/back = return empty or current value
            if ((uint8_t)ch == 0x1b || ch == KLEFT) return val;
            // All other chars including . , ; / are valid in text fields (IP addresses etc.)
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

// Pure file browser — only shows .conf files. Returns true if one was loaded.
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
    if (ch < 0) return false;  // , = back, no change

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
    // Build password display string based on setting
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
        // All hidden
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

    // Name
    { String v = typeText(isNew?"New Profile":"Edit Profile","Profile name:",p.name);
      if (v.isEmpty() && isNew) return;
      strncpy(p.name, v.c_str(), sizeof(p.name)-1); }

    // Host
    { String v = typeText(p.name,"Host / IP:",p.host);
      strncpy(p.host, v.c_str(), sizeof(p.host)-1); }

    // Port
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

    // User
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

    // Password
    if (isNew) {
        // New profile — no existing password, just prompt directly
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

    // WireGuard on/off
    { const char* wo[]={ "No WireGuard","Use WireGuard" };
      int ch=pickStr(wo,2,"WireGuard",p.useWG?1:0);
      if (ch>=0) p.useWG=(ch==1);
    }

    // WireGuard config — explicit two-option menu, always both visible
    if (p.useWG) {
        const char* wgOpts[] = { "Pick config file", "Enter keys manually" };
        int wgChoice = pickStr(wgOpts, 2, "WG config source");
        if (wgChoice == 0) {
            // File picker — show .conf files from SD
            pickWGConf(p);
        } else if (wgChoice == 1) {
            // Manual entry
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
        // wgChoice == -1 (Esc) = keep whatever is already set
    }

    // Save?
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

        // Marquee tick for profile names
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
    // Truncate SSID display to avoid overflow
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
    WiFi.disconnect(true);   // true = erase AP to fully reset radio state
    vTaskDelay(500 / portTICK_PERIOD_MS);

    // Synchronous scan — simpler and more reliable on ESP32
    int found = WiFi.scanNetworks(false, true);  // false=sync, true=show hidden

    if (found <= 0) {
        bprint("", C_DIM);
        bprint(found == 0 ? "No networks found." : "Scan failed.", found == 0 ? C_WARN : C_ERR);
        bprint("< to go back", C_DIM);
        while (waitCh() != KLEFT) {}
        WiFi.scanDelete();
        return;
    }
    if (found > MAX_NET) found = MAX_NET;

    // Save what we need BEFORE scanDelete wipes the scan results
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
        // Keep "Scan" label short — only show first 10 chars of SSID
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
        if (ch<0||strcmp(opts[ch],"Back")==0) return;   // Esc or Back = return
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
//  SETTINGS SCREEN
// ═══════════════════════════════════════════════════════════════════════════════

void runSettings() {
    while (true) {
        // Build display strings showing current values inline
        char scrBuf[32], sshBuf[32], wfiBuf[32];
        char brtBuf[32], fntBuf[32], kaBuf[32], buzBuf[32], portBuf[32];

        if (g_cfg.screenTimeoutSec<=0) snprintf(scrBuf,sizeof(scrBuf),"Screen dim: Never");
        else snprintf(scrBuf,sizeof(scrBuf),"Screen dim: %ds",g_cfg.screenTimeoutSec);

        if (g_cfg.sshTimeoutMin<=0) snprintf(sshBuf,sizeof(sshBuf),"SSH idle: Never");
        else snprintf(sshBuf,sizeof(sshBuf),"SSH idle: %dmin",g_cfg.sshTimeoutMin);

        if (g_cfg.wifiTimeoutMin<=0) snprintf(wfiBuf,sizeof(wfiBuf),"WiFi retry: Never");
        else snprintf(wfiBuf,sizeof(wfiBuf),"WiFi retry: %dmin",g_cfg.wifiTimeoutMin);

        snprintf(brtBuf, sizeof(brtBuf), "Brightness: %d%%",
                 (int)(g_cfg.brightness * 100 / 255));
        snprintf(fntBuf, sizeof(fntBuf), "Term font: size %d", g_cfg.termFontSize);
        snprintf(kaBuf,  sizeof(kaBuf),  "SSH keepalive: %s", g_cfg.keepAlive?"On":"Off");
        snprintf(buzBuf, sizeof(buzBuf), "Buzzer: %s", g_cfg.buzzer?"On":"Off");
        snprintf(portBuf,sizeof(portBuf),"Default port: %d", g_cfg.defaultPort);

        char acBuf[32];
        snprintf(acBuf, sizeof(acBuf), "Auto-connect WiFi: %s", g_cfg.autoConnect?"On":"Off");

        char pdBuf[40];
        const char* pdNames[] = {"Hidden (****)", "Last 3 chars", "Visible"};
        snprintf(pdBuf, sizeof(pdBuf), "Passwords: %s", pdNames[g_cfg.passDisplay]);

        const char* opts[] = {
            scrBuf, sshBuf, wfiBuf,
            brtBuf, fntBuf, kaBuf, buzBuf, portBuf, acBuf, pdBuf,
            "< Back"
        };
        int ch = pickStr(opts, 11, "Settings");
        if (ch < 0 || ch == 10) return;

        if (ch == 0) {
            const char* sc[] = { "Never","10s","30s","1min","2min","5min","10min" };
            int vals[] = { 0,10,30,60,120,300,600 };
            int cur = 0;
            for (int i=0;i<7;i++) if(vals[i]==g_cfg.screenTimeoutSec){cur=i;break;}
            int pick = pickStr(sc,7,"Screen dim timeout",cur);
            if (pick>=0) { g_cfg.screenTimeoutSec=vals[pick]; saveSettings(); }

        } else if (ch == 1) {
            const char* sc[] = { "Never","5min","10min","30min","1hr","2hr" };
            int vals[] = { 0,5,10,30,60,120 };
            int cur = 0;
            for (int i=0;i<6;i++) if(vals[i]==g_cfg.sshTimeoutMin){cur=i;break;}
            int pick = pickStr(sc,6,"SSH idle timeout",cur);
            if (pick>=0) { g_cfg.sshTimeoutMin=vals[pick]; saveSettings(); }

        } else if (ch == 2) {
            const char* sc[] = { "Never","1min","5min","15min","30min" };
            int vals[] = { 0,1,5,15,30 };
            int cur = 0;
            for (int i=0;i<5;i++) if(vals[i]==g_cfg.wifiTimeoutMin){cur=i;break;}
            int pick = pickStr(sc,5,"WiFi retry interval",cur);
            if (pick>=0) { g_cfg.wifiTimeoutMin=vals[pick]; saveSettings(); }

        } else if (ch == 3) {
            const char* sc[] = { "25%","50%","75%","100%" };
            int vals[] = { 64,128,192,255 };
            int cur = 1;
            for (int i=0;i<4;i++) if(abs(vals[i]-g_cfg.brightness)<32){cur=i;break;}
            int pick = pickStr(sc,4,"Display brightness",cur);
            if (pick>=0) {
                g_cfg.brightness=vals[pick];
                M5Cardputer.Display.setBrightness(g_cfg.brightness);
                saveSettings();
            }

        } else if (ch == 4) {
            const char* sc[] = { "Size 1 (more text)","Size 2 (larger)" };
            int pick = pickStr(sc,2,"Terminal font size", g_cfg.termFontSize==2?1:0);
            if (pick>=0) { g_cfg.termFontSize=(pick==1)?2:1; saveSettings(); }

        } else if (ch == 5) {
            const char* sc[] = { "On (recommended)","Off" };
            int pick = pickStr(sc,2,"SSH keepalive", g_cfg.keepAlive?0:1);
            if (pick>=0) { g_cfg.keepAlive=(pick==0); saveSettings(); }

        } else if (ch == 6) {
            const char* sc[] = { "Off","On" };
            int pick = pickStr(sc,2,"Buzzer", g_cfg.buzzer?1:0);
            if (pick>=0) { g_cfg.buzzer=(pick==1); saveSettings(); }

        } else if (ch == 7) {
            const char* sc[] = { "22 (SSH)","443 (HTTPS)","2222","Custom" };
            int vals[] = { 22,443,2222,0 };
            int cur = 0;
            for (int i=0;i<3;i++) if(vals[i]==g_cfg.defaultPort){cur=i;break;}
            int pick = pickStr(sc,4,"Default SSH port",cur);
            if (pick==3) {
                char buf[8]; snprintf(buf,sizeof(buf),"%d",g_cfg.defaultPort);
                String v = typeText("Default port","Port number:",buf);
                int pv = v.toInt();
                if (pv>0) { g_cfg.defaultPort=pv; saveSettings(); }
            } else if (pick>=0) {
                g_cfg.defaultPort=vals[pick]; saveSettings();
            }
        } else if (ch == 8) {
            const char* sc[] = { "On (connect at boot)","Off" };
            int pick = pickStr(sc,2,"Auto-connect WiFi", g_cfg.autoConnect?0:1);
            if (pick>=0) { g_cfg.autoConnect=(pick==0); saveSettings(); }

        } else if (ch == 9) {
            const char* sc[] = { "Hidden (****)", "Show last 3 chars", "Show full password" };
            int pick = pickStr(sc,3,"Password display", g_cfg.passDisplay);
            if (pick>=0) { g_cfg.passDisplay=pick; saveSettings(); }
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  HOME SCREEN
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
//  HOME SCREEN  –  Bruce-style: full screen, one item at a time, ,/ to navigate
// ═══════════════════════════════════════════════════════════════════════════════

// Draw a proper WiFi fan icon centred at cx,cy — same visual size as gear (r~16)
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
    // teeth at 0,60,120,180,240,300 degrees
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

    // Full-screen tile for current selection
    uint16_t tileColors[3] = {C_WIFI, C_PROF, C_SETT};
    const char* labels[] = {"WiFi", "Profiles", "Settings"};
    uint16_t col = tileColors[sel];

    // Layout constants (all pixel-precise):
    // Content area: y=0..116 (status bar at 117)
    // Up-triangle tip y=6, base y=12
    // Down-triangle tip y=110, base y=104
    // Usable band: y=14..102 = 88px, centre=58
    // Block: icon 40px + 6px gap + label 16px = 62px, half=31
    // Icon cy = 58-31+20 = 47, label top = 69

    // Up triangle ▲ — tip at top (y=6, 1px), base at bottom (y=12, wide)
    if (sel > 0) {
        int ax = DW/2;
        for (int i = 0; i < 7; i++)
            M5Cardputer.Display.drawLine(ax-i, 6+i, ax+i, 6+i, C_DIM);
    }
    // Down triangle ▼ — wide at top (y=104), tip at bottom (y=110, 1px)
    if (sel < 2) {
        int ax = DW/2;
        for (int i = 0; i < 7; i++)
            M5Cardputer.Display.drawLine(ax-(6-i), 104+i, ax+(6-i), 104+i, C_DIM);
    }

    // Vertical position dots on right edge (centred in content area)
    for (int i = 0; i < 3; i++) {
        int dx = DW - 8;
        int dy = 58 - 16 + i*16;
        if (i == sel)
            M5Cardputer.Display.fillCircle(dx, dy, 4, col);
        else
            M5Cardputer.Display.drawCircle(dx, dy, 3, C_DIM);
    }

    // Icon centred in band
    int cx = DW / 2;
    int cy = 47;
    if (sel == 0)      drawWifiIcon(cx, cy, col);
    else if (sel == 1) drawSshIcon(cx, cy, col, C_BG);
    else               drawGearIcon(cx, cy, col);

    // Label below icon
    M5Cardputer.Display.setTextSize(2);
    M5Cardputer.Display.setTextColor(col, C_BG);
    int lw = strlen(labels[sel]) * 12;
    M5Cardputer.Display.setCursor(cx - lw/2, cy + 22);
    M5Cardputer.Display.print(labels[sel]);

    // Status bar at bottom
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

// Task that runs ssh_connect / auth / channel open — needs big stack
static void sshConnectTask(void* arg) {
    SSHTaskCtx* ctx = (SSHTaskCtx*)arg;
    const Profile& p = ctx->prof;

    ctx->sess = ssh_new();
    if (!ctx->sess) {
        strlcpy(ctx->errmsg, "ssh_new failed", sizeof(ctx->errmsg));
        ctx->state = 2; vTaskDelete(NULL); return;
    }

    int verb = SSH_LOG_NOLOG, port = p.port;
    ssh_options_set(ctx->sess, SSH_OPTIONS_HOST, p.host);
    ssh_options_set(ctx->sess, SSH_OPTIONS_USER, p.user);
    ssh_options_set(ctx->sess, SSH_OPTIONS_PORT, &port);
    ssh_options_set(ctx->sess, SSH_OPTIONS_LOG_VERBOSITY, &verb);
    if (g_cfg.keepAlive) {
        int ka = 60; ssh_options_set(ctx->sess, SSH_OPTIONS_TIMEOUT, &ka);
    }

    if (ssh_connect(ctx->sess) != SSH_OK) {
        snprintf(ctx->errmsg, sizeof(ctx->errmsg), "Conn: %s", ssh_get_error(ctx->sess));
        ssh_free(ctx->sess); ctx->sess = nullptr;
        ctx->state = 2; vTaskDelete(NULL); return;
    }
    if (ssh_userauth_password(ctx->sess, nullptr, p.pass) != SSH_AUTH_SUCCESS) {
        strlcpy(ctx->errmsg, "Auth failed", sizeof(ctx->errmsg));
        ssh_disconnect(ctx->sess); ssh_free(ctx->sess); ctx->sess = nullptr;
        ctx->state = 2; vTaskDelete(NULL); return;
    }

    ctx->ch = ssh_channel_new(ctx->sess);

    // Calculate terminal dimensions based on font size
    // Display is 240x123px usable. Font1 = 6px wide, 8px tall. Font2 = 12x16.
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

    // Override PS1 and suppress the echo — drain output for 500ms before handing off
    vTaskDelay(300 / portTICK_PERIOD_MS);
    ssh_channel_write(ctx->ch, "export PS1='\\$ '\r", 17);
    vTaskDelay(500 / portTICK_PERIOD_MS);
    char drain[256];
    while (ssh_channel_read_nonblocking(ctx->ch, drain, sizeof(drain), 0) > 0) {}
    // Send a blank line to get a fresh prompt
    ssh_channel_write(ctx->ch, "\r", 1);
    vTaskDelay(150 / portTICK_PERIOD_MS);
    while (ssh_channel_read_nonblocking(ctx->ch, drain, sizeof(drain), 0) > 0) {}

    ctx->state = 1;   // connected — main task takes over
    vTaskDelete(NULL);
}

void runConnect(int idx) {
    // copy profile so task has its own copy
    g_sshCtx.prof  = g_prof[idx];
    g_sshCtx.sess  = nullptr;
    g_sshCtx.ch    = nullptr;
    g_sshCtx.state = 0;
    g_sshCtx.errmsg[0] = '\0';

    const Profile& p = g_sshCtx.prof;
    screenInit(p.name, "");

    // WireGuard setup (runs on main task, no big stack needed)
    if (p.useWG) {
        if (g_wgActive) { bprint("Stopping WG...", C_DIM); g_wgActive = false; }
        bprint("WireGuard...", C_DIM);
        IPAddress tun;
        String a = p.wg_addr; int sl = a.indexOf('/'); if (sl >= 0) a = a.substring(0, sl);
        if (!tun.fromString(a)) { bprint("Bad WG IP!", C_ERR); delay(2000); return; }
        String ep = p.wg_endpoint;
        int co = ep.lastIndexOf(':');
        if (co < 0) { bprint("Bad WG endpoint!", C_ERR); delay(2000); return; }
        configTime(0, 0, "pool.ntp.org", "time.google.com"); delay(800);
        if (!g_wg) g_wg = new WireGuard();
        g_wg->begin(tun, p.wg_privkey, ep.substring(0, co).c_str(),
                   p.wg_pubkey, ep.substring(co + 1).toInt());
        g_wgActive = true;
        bprint("WG up.", C_OK);
    }

    // Spawn SSH connect task with 32 KB stack on core 0
    bprint("SSH connecting...", C_DIM);
    TaskHandle_t th = nullptr;
    xTaskCreatePinnedToCore(sshConnectTask, "ssh_conn", 32768,
                            &g_sshCtx, 5, &th, 0);
    if (!th) {
        bprint("Task create failed!", C_ERR); delay(2000); return;
    }

    // Wait for task to finish, show spinner dots
    unsigned long t0 = millis();
    while (g_sshCtx.state == 0) {
        if ((millis() - t0) > 30000UL) {
            bprint("Timeout!", C_ERR); delay(2000);
            if (p.useWG) g_wgActive = false;
            return;
        }
        vTaskDelay(200 / portTICK_PERIOD_MS);
        M5Cardputer.Display.print('.');
    }

    if (g_sshCtx.state == 2) {
        bprintf(C_ERR, "%s", g_sshCtx.errmsg);
        delay(2500);
        if (p.useWG) g_wgActive = false;
        return;
    }

    // state == 1: connected — run terminal on main task
    ssh_session sess = g_sshCtx.sess;
    ssh_channel ch   = g_sshCtx.ch;

    M5Cardputer.Display.fillScreen(C_BG);
    titleBar(p.name);
    hintBar("G0/Fn+Q=quit  Fn+F=font  Ctrl=^");
    M5Cardputer.Display.setTextSize(g_cfg.termFontSize);
    M5Cardputer.Display.setCursor(0, TITLEH + 2);
    g_termY = TITLEH + 2;

    runSSHTerm(sess, ch);

    ssh_channel_close(ch); ssh_channel_free(ch);
    ssh_disconnect(sess);  ssh_free(sess);

    if (p.useWG) g_wgActive = false;
    screenInit(p.name, "Any key to return");
    bprint("Session ended.", C_DIM);
    waitCh();
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SSH TERMINAL
// ═══════════════════════════════════════════════════════════════════════════════

void runSSHTerm(ssh_session sess, ssh_channel ch) {
    int lim = DH - HINTH - LHS;
    unsigned long sshLastActivity = millis();

    // Helper: update hint bar with current font size
    auto showHint = [&]() {
        char hbuf[48];
        snprintf(hbuf, sizeof(hbuf), "G0/Fn+Q=quit Fn+;.,/=arrows Ctrl=^", g_cfg.termFontSize);
        hintBar(hbuf);
        M5Cardputer.Display.setTextSize(g_cfg.termFontSize);
    };
    showHint();

    while (true) {
        vTaskDelay(8/portTICK_PERIOD_MS);
        M5Cardputer.update();

        // BtnG0 (physical button on top) = quit
        if (M5Cardputer.BtnA.wasPressed()) break;

        // SSH idle timeout
        if (g_cfg.sshTimeoutMin > 0) {
            if ((millis()-sshLastActivity) > (unsigned long)g_cfg.sshTimeoutMin*60000UL) {
                break;
            }
        }
        // Screen timeout — dim only, keep session alive
        if (g_cfg.screenTimeoutSec > 0 && !g_dimmed) {
            if ((millis()-g_lastAct) > (unsigned long)g_cfg.screenTimeoutSec*1000UL) {
                M5Cardputer.Display.setBrightness(0);
                g_dimmed = true;
            }
        }

        if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
            unsigned long now = millis();
            if (now - g_lastKey >= DEBOUNCE_MS) {
                g_lastKey = now;
                touchActivity();
                sshLastActivity = now;
                auto st = M5Cardputer.Keyboard.keysState();
                bool fn   = isFn(st);
                bool ctrl = isCtrl(st);

                if (fn) {
                    // Fn held — check hid_keys for which base key was pressed
                    for (auto hid : st.hid_keys) {
                        char alpha = hidToAlpha(hid);
                        if (alpha == 'q') goto done;           // Fn+Q = quit
                        if (alpha == 'f') {                    // Fn+F = cycle font size
                            g_cfg.termFontSize = (g_cfg.termFontSize == 1) ? 2 : 1;
                            saveSettings();
                            // Clear terminal body and reset cursor
                            M5Cardputer.Display.fillRect(0, TITLEH, DW, DH - TITLEH - HINTH, C_BG);
                            M5Cardputer.Display.setCursor(0, TITLEH + 2);
                            g_termY = TITLEH + 2;
                            showHint();
                            // Tell server about new PTY dimensions
                            int newCols = (g_cfg.termFontSize == 2) ? 20 : 40;
                            int newRows = (g_cfg.termFontSize == 2) ?  7 : 14;
                            ssh_channel_change_pty_size(ch, newCols, newRows);
                        }
                        // Fn + ; . , /  → arrow keys
                        if (hid == 0x33) { ssh_channel_write(ch,"\x1b[A",3); } // Fn+; = up
                        if (hid == 0x37) { ssh_channel_write(ch,"\x1b[B",3); } // Fn+. = down
                        if (hid == 0x36) { ssh_channel_write(ch,"\x1b[D",3); } // Fn+, = left
                        if (hid == 0x38) { ssh_channel_write(ch,"\x1b[C",3); } // Fn+/ = right
                    }
                } else if (ctrl) {
                    // Ctrl held — hid_keys gives base letter, convert to ctrl char
                    for (auto hid : st.hid_keys) {
                        char alpha = hidToAlpha(hid);
                        if (alpha) {
                            char ctrl_char = alpha - 'a' + 1;  // a=1, c=3, d=4, z=26...
                            ssh_channel_write(ch, &ctrl_char, 1);
                        }
                    }
                } else {
                    // Normal keys — ; . , / type as characters, no arrow interception
                    for (auto c : st.word) {
                        if ((uint8_t)c == 0x1B) { ssh_channel_write(ch,"\x1b",1); continue; }
                        ssh_channel_write(ch, &c, 1);
                    }
                    if (st.del) {
                        char bs = 0x7F;
                        ssh_channel_write(ch, &bs, 1);
                    }
                    if (st.enter) {
                        const char cr = '\r';
                        ssh_channel_write(ch, &cr, 1);
                    }
                }
            }
        }

        // SSH output — render to display
        char rbuf[256];
        int n = ssh_channel_read_nonblocking(ch, rbuf, sizeof(rbuf), 0);
        if (n > 0) {
            sshLastActivity = millis();
            bool inEsc = false, inCSI = false;
            for (int i = 0; i < n; i++) {
                uint8_t c = rbuf[i];
                if (inCSI) {
                    if (c >= '@' && c <= '~') inCSI = false;
                    continue;
                }
                if (inEsc) {
                    inEsc = false;
                    if (c == '[') inCSI = true;
                    continue;
                }
                if (c == 0x1B) { inEsc = true; continue; }
                if (c == '\r') { M5Cardputer.Display.setCursor(0, M5Cardputer.Display.getCursorY()); continue; }
                if (c == 0x08 || c == 0x7F) {
                    // Backspace from server
                    int cx = M5Cardputer.Display.getCursorX() - (g_cfg.termFontSize * 6);
                    int cy = M5Cardputer.Display.getCursorY();
                    if (cx < 0) cx = 0;
                    M5Cardputer.Display.setCursor(cx, cy);
                    M5Cardputer.Display.print(' ');
                    M5Cardputer.Display.setCursor(cx, cy);
                    continue;
                }
                // Scroll if needed
                if (M5Cardputer.Display.getCursorY() > lim) {
                    M5Cardputer.Display.scroll(0, -(g_cfg.termFontSize * 8));
                    M5Cardputer.Display.fillRect(0, lim, DW, g_cfg.termFontSize*8, C_BG);
                    M5Cardputer.Display.setCursor(0, lim);
                }
                M5Cardputer.Display.write(c);
                g_termY = M5Cardputer.Display.getCursorY();
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
    runHome();
}

void loop() { vTaskDelay(50/portTICK_PERIOD_MS); }
