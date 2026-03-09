/*
 * SSH Client with Profile Manager
 * For M5Cardputer and M5Cardputer-Adv
 *
 * Required library versions:
 *   M5Stack Board Manager  >= 3.2.2
 *   M5Cardputer            >= 1.1.1
 *   M5Unified              >= 0.2.8
 *   M5GFX                  >= 0.2.10
 *   WireGuard-ESP32
 *   libssh_esp32
 *
 * SD card layout:
 *   /profiles/wifi.cfg        - saved WiFi credentials
 *   /profiles/<n>.prof        - one file per SSH profile
 *   /profiles/wg/<n>.conf     - standard WireGuard config files
 *                               (copy these here from your PC / phone)
 *
 * Profile format (/profiles/<n>.prof):
 *   name=MyServer
 *   host=192.168.1.1
 *   user=admin
 *   pass=secret
 *   wg=1                      (0 = no WireGuard, 1 = use WireGuard)
 *   wg_conffile=work.conf     (source filename, stored for reference)
 *   wg_privkey=<base64>
 *   wg_addr=10.0.0.2/24
 *   wg_pubkey=<base64>
 *   wg_endpoint=1.2.3.4:51820
 *
 * WireGuard .conf format (/profiles/wg/<n>.conf):
 *   [Interface]
 *   PrivateKey = <base64>
 *   Address    = 10.0.0.2/24
 *   [Peer]
 *   PublicKey  = <base64>
 *   Endpoint   = 1.2.3.4:51820
 *   AllowedIPs = 0.0.0.0/0
 *
 * Navigation (menus):
 *   Fn+W / Fn+S  = move up / down
 *   Enter        = confirm / select / connect
 *   Fn+N         = new profile
 *   Fn+E         = edit selected profile
 *   Fn+D         = delete selected profile
 *
 * Navigation (WG config picker):
 *   Fn+W / Fn+S  = scroll list
 *   Enter        = use selected .conf file
 *   Fn+M         = enter keys manually instead
 *
 * During SSH session:
 *   Fn+C        = Ctrl-C
 *   Fn+X        = Ctrl-D (exit / logout)
 *   Fn+Z        = Ctrl-Z
 *   Fn+L        = Ctrl-L (clear screen)
 *   Fn+E        = ESC
 *   Fn+W/A/S/D  = arrow keys (up / left / down / right)
 */

#include <WiFi.h>
#include <M5Cardputer.h>
#include <WireGuard-ESP32.h>
#include <SD.h>
#include <FS.h>
#include "libssh_esp32.h"
#include <libssh/libssh.h>

// ── Colours ───────────────────────────────────────────────────────────────────
#define COL_BG      TFT_BLACK
#define COL_FG      TFT_WHITE
#define COL_SEL_BG  0x2945
#define COL_SEL_FG  TFT_WHITE
#define COL_TITLE   TFT_CYAN
#define COL_OK      TFT_GREEN
#define COL_ERR     TFT_RED
#define COL_DIM     0x7BEF
#define COL_HINT_BG 0x2104

#define LINE_H       14
#define MAX_PROFILES 20
#define MAX_WG_FILES 30

// ── Profile struct ────────────────────────────────────────────────────────────
struct Profile {
    char name[32];
    char host[64];
    char user[64];
    char pass[64];
    bool useWG;
    char wg_conffile[32];   // source .conf filename, for reference
    char wg_privkey[48];
    char wg_addr[20];
    char wg_pubkey[48];
    char wg_endpoint[32];
};

// ── Globals ───────────────────────────────────────────────────────────────────
Profile       profiles[MAX_PROFILES];
int           profileCount = 0;
int           selectedIdx  = 0;

static WireGuard wg;
bool          wgActive     = false;

int           termCursorY  = 0;
unsigned long lastKeyMs    = 0;
const unsigned long DEBOUNCE_MS = 150;

enum AppState { STATE_WIFI_SETUP, STATE_PROFILE_LIST,
                STATE_PROFILE_EDIT, STATE_CONNECTING, STATE_SSH_TERMINAL };
AppState appState = STATE_WIFI_SETUP;

const char* WIFI_CRED_FILE = "/profiles/wifi.cfg";
const char* WG_DIR         = "/profiles/wg";
char g_ssid[64]            = "";
char g_wifiPass[64]        = "";

// ── Forward declarations ──────────────────────────────────────────────────────
void     drawTitle(const char* t);
void     printLine(const char* msg, uint16_t col = COL_FG);
void     printLinef(uint16_t col, const char* fmt, ...);
String   readInput(const char* prompt, bool hidden = false);
bool     readYN(const char* prompt);
void     scrollUp();
inline bool isFn(const Keyboard_Class::KeysState& s);
Keyboard_Class::KeysState waitKey();

void     loadAllProfiles();
void     saveProfile(const Profile& p);
void     deleteProfile(int idx);
bool     parseProfileFile(File& f, Profile& p);
String   profilePath(const char* name);
void     saveWifiCreds(const char* ssid, const char* pass);
bool     loadWifiCreds(String& ssid, String& pass);

void     runWifiSetup();
void     runProfileList();
void     drawProfileList();
void     runProfileEdit(int idx);

bool     pickWGConfig(Profile& p);
bool     parseWGConfFile(const char* path, Profile& p);
void     drawWGPicker(const char wgFiles[][32], int count, int sel, int scroll);

void     runConnect(int idx);
void     wgConnect(const Profile& p);
void     wgDisconnect();

ssh_session sshConnect(const char* host, const char* user);
bool        sshAuth(ssh_session s, const char* pass);
ssh_channel sshOpenShell(ssh_session s);
void        runSSHTerminal(ssh_session sess, ssh_channel ch);


// ═══════════════════════════════════════════════════════════════════════════════
//  SETUP
// ═══════════════════════════════════════════════════════════════════════════════
void setup() {
    auto cfg = M5.config();
    M5Cardputer.begin(cfg, true);
    M5Cardputer.Display.setRotation(1);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextColor(COL_FG, COL_BG);
    M5Cardputer.Display.fillScreen(COL_BG);
    Serial.begin(115200);

    if (!SD.begin(M5.getPin(m5::pin_name_t::sd_spi_ss))) {
        drawTitle("SSH Client");
        printLine("SD mount failed!", COL_ERR);
        printLine("Profiles unavailable.", COL_DIM);
        delay(2000);
    } else {
        if (!SD.exists("/profiles")) SD.mkdir("/profiles");
        if (!SD.exists(WG_DIR))      SD.mkdir(WG_DIR);
        loadAllProfiles();
    }

    runWifiSetup();
    appState = STATE_PROFILE_LIST;
    runProfileList();
}

void loop() {
    vTaskDelay(50 / portTICK_PERIOD_MS);
}


// ═══════════════════════════════════════════════════════════════════════════════
//  DISPLAY HELPERS
// ═══════════════════════════════════════════════════════════════════════════════
void drawTitle(const char* t) {
    M5Cardputer.Display.fillScreen(COL_BG);
    M5Cardputer.Display.setTextColor(COL_TITLE, COL_BG);
    M5Cardputer.Display.setCursor(0, 0);
    M5Cardputer.Display.println(t);
    M5Cardputer.Display.drawFastHLine(0, LINE_H + 2,
        M5Cardputer.Display.width(), COL_TITLE);
    M5Cardputer.Display.setTextColor(COL_FG, COL_BG);
    M5Cardputer.Display.setCursor(0, LINE_H + 5);
    termCursorY = LINE_H + 5;
}

void printLine(const char* msg, uint16_t col) {
    if (M5Cardputer.Display.getCursorY() >
        M5Cardputer.Display.height() - LINE_H) scrollUp();
    M5Cardputer.Display.setTextColor(col, COL_BG);
    M5Cardputer.Display.println(msg);
    M5Cardputer.Display.setTextColor(COL_FG, COL_BG);
    termCursorY = M5Cardputer.Display.getCursorY();
}

void printLinef(uint16_t col, const char* fmt, ...) {
    char buf[128];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    printLine(buf, col);
}

void scrollUp() {
    int h = M5Cardputer.Display.height();
    M5Cardputer.Display.scroll(0, -LINE_H);
    M5Cardputer.Display.fillRect(0, h - LINE_H,
        M5Cardputer.Display.width(), LINE_H, COL_BG);
    M5Cardputer.Display.setCursor(0, h - LINE_H);
    termCursorY = h - LINE_H;
}


// ═══════════════════════════════════════════════════════════════════════════════
//  INPUT HELPERS
// ═══════════════════════════════════════════════════════════════════════════════
inline bool isFn(const Keyboard_Class::KeysState& s) {
    return (s.modifiers & 0x10) != 0;
}

Keyboard_Class::KeysState waitKey() {
    while (true) {
        vTaskDelay(10 / portTICK_PERIOD_MS);
        M5Cardputer.update();
        if (M5Cardputer.Keyboard.isChange() &&
            M5Cardputer.Keyboard.isPressed())
            return M5Cardputer.Keyboard.keysState();
    }
}

String readInput(const char* prompt, bool hidden) {
    M5Cardputer.Display.setTextColor(COL_DIM, COL_BG);
    M5Cardputer.Display.print(prompt);
    M5Cardputer.Display.print(": ");
    M5Cardputer.Display.setTextColor(COL_FG, COL_BG);

    String input = "";
    int startX = M5Cardputer.Display.getCursorX();
    int startY = M5Cardputer.Display.getCursorY();

    while (true) {
        vTaskDelay(10 / portTICK_PERIOD_MS);
        M5Cardputer.update();
        if (!M5Cardputer.Keyboard.isChange() ||
            !M5Cardputer.Keyboard.isPressed()) continue;

        Keyboard_Class::KeysState st = M5Cardputer.Keyboard.keysState();

        if (st.enter) { M5Cardputer.Display.println(); return input; }

        if (st.del && !input.isEmpty()) {
            input.remove(input.length() - 1);
            M5Cardputer.Display.fillRect(startX, startY,
                M5Cardputer.Display.width() - startX, LINE_H, COL_BG);
            M5Cardputer.Display.setCursor(startX, startY);
            if (hidden) for (int i = 0; i < (int)input.length(); i++)
                M5Cardputer.Display.print('*');
            else
                M5Cardputer.Display.print(input);
            continue;
        }

        for (auto ch : st.word) {
            input += ch;
            M5Cardputer.Display.print(hidden ? '*' : ch);
        }
    }
}

bool readYN(const char* prompt) {
    M5Cardputer.Display.setTextColor(COL_DIM, COL_BG);
    M5Cardputer.Display.print(prompt);
    M5Cardputer.Display.print(" (Y/N): ");
    M5Cardputer.Display.setTextColor(COL_FG, COL_BG);
    while (true) {
        vTaskDelay(10 / portTICK_PERIOD_MS);
        M5Cardputer.update();
        if (!M5Cardputer.Keyboard.isChange() ||
            !M5Cardputer.Keyboard.isPressed()) continue;
        Keyboard_Class::KeysState st = M5Cardputer.Keyboard.keysState();
        for (auto ch : st.word) {
            if (ch == 'y' || ch == 'Y') { M5Cardputer.Display.println("Y"); return true;  }
            if (ch == 'n' || ch == 'N') { M5Cardputer.Display.println("N"); return false; }
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  PROFILE FILE I/O
// ═══════════════════════════════════════════════════════════════════════════════
String profilePath(const char* name) {
    return String("/profiles/") + name + ".prof";
}

bool parseProfileFile(File& f, Profile& p) {
    memset(&p, 0, sizeof(p));
    while (f.available()) {
        String line = f.readStringUntil('\n'); line.trim();
        if (line.isEmpty() || line.startsWith("#")) continue;
        int eq = line.indexOf('=');
        if (eq < 0) continue;
        String key = line.substring(0, eq);
        String val = line.substring(eq + 1);
        key.trim(); val.trim();

        if      (key == "name")        strncpy(p.name,        val.c_str(), sizeof(p.name)        - 1);
        else if (key == "host")        strncpy(p.host,        val.c_str(), sizeof(p.host)        - 1);
        else if (key == "user")        strncpy(p.user,        val.c_str(), sizeof(p.user)        - 1);
        else if (key == "pass")        strncpy(p.pass,        val.c_str(), sizeof(p.pass)        - 1);
        else if (key == "wg")          p.useWG = (val == "1");
        else if (key == "wg_conffile") strncpy(p.wg_conffile, val.c_str(), sizeof(p.wg_conffile) - 1);
        else if (key == "wg_privkey")  strncpy(p.wg_privkey,  val.c_str(), sizeof(p.wg_privkey)  - 1);
        else if (key == "wg_addr")     strncpy(p.wg_addr,     val.c_str(), sizeof(p.wg_addr)     - 1);
        else if (key == "wg_pubkey")   strncpy(p.wg_pubkey,   val.c_str(), sizeof(p.wg_pubkey)   - 1);
        else if (key == "wg_endpoint") strncpy(p.wg_endpoint, val.c_str(), sizeof(p.wg_endpoint) - 1);
    }
    return p.name[0] != '\0' && p.host[0] != '\0';
}

void loadAllProfiles() {
    profileCount = 0;
    File dir = SD.open("/profiles");
    if (!dir || !dir.isDirectory()) return;
    File entry;
    while ((entry = dir.openNextFile()) && profileCount < MAX_PROFILES) {
        String fname = String(entry.name());
        if (fname.endsWith(".prof")) {
            Profile p;
            if (parseProfileFile(entry, p)) profiles[profileCount++] = p;
        }
        entry.close();
    }
    dir.close();
}

void saveProfile(const Profile& p) {
    String path = profilePath(p.name);
    SD.remove(path.c_str());
    File f = SD.open(path.c_str(), FILE_WRITE);
    if (!f) { printLine("Save failed!", COL_ERR); return; }
    f.printf("name=%s\n",        p.name);
    f.printf("host=%s\n",        p.host);
    f.printf("user=%s\n",        p.user);
    f.printf("pass=%s\n",        p.pass);
    f.printf("wg=%d\n",          p.useWG ? 1 : 0);
    f.printf("wg_conffile=%s\n", p.wg_conffile);
    f.printf("wg_privkey=%s\n",  p.wg_privkey);
    f.printf("wg_addr=%s\n",     p.wg_addr);
    f.printf("wg_pubkey=%s\n",   p.wg_pubkey);
    f.printf("wg_endpoint=%s\n", p.wg_endpoint);
    f.close();
}

void deleteProfile(int idx) {
    if (idx < 0 || idx >= profileCount) return;
    SD.remove(profilePath(profiles[idx].name).c_str());
    for (int i = idx; i < profileCount - 1; i++) profiles[i] = profiles[i + 1];
    profileCount--;
    if (selectedIdx >= profileCount && selectedIdx > 0) selectedIdx--;
}

void saveWifiCreds(const char* ssid, const char* pass) {
    SD.remove(WIFI_CRED_FILE);
    File f = SD.open(WIFI_CRED_FILE, FILE_WRITE);
    if (!f) return;
    f.println(ssid); f.print(pass); f.close();
}

bool loadWifiCreds(String& ssid, String& pass) {
    File f = SD.open(WIFI_CRED_FILE, FILE_READ);
    if (!f) return false;
    ssid = f.readStringUntil('\n'); ssid.trim();
    pass = f.readStringUntil('\n'); pass.trim();
    f.close();
    return ssid.length() > 0;
}


// ═══════════════════════════════════════════════════════════════════════════════
//  WIREGUARD CONFIG FILE PICKER
// ═══════════════════════════════════════════════════════════════════════════════

// Parse a standard WireGuard .conf file into the WG fields of p.
// Returns true if PrivateKey and Endpoint were found.
bool parseWGConfFile(const char* path, Profile& p) {
    File f = SD.open(path, FILE_READ);
    if (!f) return false;

    p.wg_privkey[0] = p.wg_addr[0] = p.wg_pubkey[0] = p.wg_endpoint[0] = '\0';

    while (f.available()) {
        String line = f.readStringUntil('\n'); line.trim();
        if (line.isEmpty() || line.startsWith("[") || line.startsWith("#")) continue;
        int eq = line.indexOf('=');
        if (eq < 0) continue;
        String key = line.substring(0, eq);
        String val = line.substring(eq + 1);
        key.trim(); val.trim();

        if      (key == "PrivateKey") strncpy(p.wg_privkey,  val.c_str(), sizeof(p.wg_privkey)  - 1);
        else if (key == "Address")    strncpy(p.wg_addr,     val.c_str(), sizeof(p.wg_addr)     - 1);
        else if (key == "PublicKey")  strncpy(p.wg_pubkey,   val.c_str(), sizeof(p.wg_pubkey)   - 1);
        else if (key == "Endpoint")   strncpy(p.wg_endpoint, val.c_str(), sizeof(p.wg_endpoint) - 1);
    }
    f.close();
    return p.wg_privkey[0] != '\0' && p.wg_endpoint[0] != '\0';
}

void drawWGPicker(const char wgFiles[][32], int count, int sel, int scroll) {
    int dispW   = M5Cardputer.Display.width();
    int dispH   = M5Cardputer.Display.height();
    int titleH  = LINE_H + 5;
    int hintH   = LINE_H + 2;
    int visRows = (dispH - titleH - hintH) / LINE_H;

    M5Cardputer.Display.fillScreen(COL_BG);

    // Title bar
    M5Cardputer.Display.fillRect(0, 0, dispW, LINE_H + 2, COL_TITLE);
    M5Cardputer.Display.setTextColor(COL_BG, COL_TITLE);
    M5Cardputer.Display.setCursor(2, 1);
    M5Cardputer.Display.print("Select WG Config");
    M5Cardputer.Display.setTextColor(COL_FG, COL_BG);

    // Hint bar
    M5Cardputer.Display.fillRect(0, dispH - hintH, dispW, hintH, COL_HINT_BG);
    M5Cardputer.Display.setTextColor(COL_DIM, COL_HINT_BG);
    M5Cardputer.Display.setCursor(2, dispH - LINE_H);
    M5Cardputer.Display.print("Enter:use  Fn+M:manual  Fn+W/S:nav");
    M5Cardputer.Display.setTextColor(COL_FG, COL_BG);

    if (count == 0) {
        M5Cardputer.Display.setCursor(4, titleH + 6);
        M5Cardputer.Display.setTextColor(COL_DIM, COL_BG);
        M5Cardputer.Display.println("No .conf files found.");
        M5Cardputer.Display.println("Copy them to:");
        M5Cardputer.Display.println("/profiles/wg/");
        M5Cardputer.Display.println("Press Fn+M to type manually.");
        M5Cardputer.Display.setTextColor(COL_FG, COL_BG);
        return;
    }

    for (int i = 0; i < visRows && (i + scroll) < count; i++) {
        int fi  = i + scroll;
        int y   = titleH + i * LINE_H;
        bool hi = (fi == sel);
        if (hi) {
            M5Cardputer.Display.fillRect(0, y, dispW, LINE_H, COL_SEL_BG);
            M5Cardputer.Display.setTextColor(COL_SEL_FG, COL_SEL_BG);
        } else {
            M5Cardputer.Display.setTextColor(COL_FG, COL_BG);
        }
        M5Cardputer.Display.setCursor(4, y + 1);
        M5Cardputer.Display.print(wgFiles[fi]);
    }
    M5Cardputer.Display.setTextColor(COL_FG, COL_BG);
}

// Show the picker.
// Returns true  → file chosen and parsed into p's WG fields.
// Returns false → user pressed Fn+M (manual entry).
bool pickWGConfig(Profile& p) {
    static char wgFiles[MAX_WG_FILES][32];
    int fileCount = 0;

    File dir = SD.open(WG_DIR);
    if (dir && dir.isDirectory()) {
        File entry;
        while ((entry = dir.openNextFile()) && fileCount < MAX_WG_FILES) {
            String fname = String(entry.name());
            if (fname.endsWith(".conf")) {
                strncpy(wgFiles[fileCount], fname.c_str(),
                        sizeof(wgFiles[fileCount]) - 1);
                wgFiles[fileCount][sizeof(wgFiles[fileCount]) - 1] = '\0';
                fileCount++;
            }
            entry.close();
        }
        dir.close();
    }

    int dispH   = M5Cardputer.Display.height();
    int titleH  = LINE_H + 5;
    int hintH   = LINE_H + 2;
    int visRows = (dispH - titleH - hintH) / LINE_H;
    int sel     = 0;
    int scroll  = 0;

    drawWGPicker(wgFiles, fileCount, sel, scroll);

    while (true) {
        Keyboard_Class::KeysState st = waitKey();
        bool fn = isFn(st);

        if (fn) {
            for (auto ch : st.word) {
                if (ch == 'w' || ch == 'W') {
                    if (sel > 0) { sel--; if (sel < scroll) scroll = sel; }
                    drawWGPicker(wgFiles, fileCount, sel, scroll);
                } else if (ch == 's' || ch == 'S') {
                    if (sel < fileCount - 1) {
                        sel++;
                        if (sel >= scroll + visRows) scroll = sel - visRows + 1;
                    }
                    drawWGPicker(wgFiles, fileCount, sel, scroll);
                } else if (ch == 'm' || ch == 'M') {
                    return false;  // manual entry
                }
            }
        } else if (st.enter) {
            if (fileCount == 0) return false;

            String path = String(WG_DIR) + "/" + wgFiles[sel];
            drawTitle("Loading WG Config");
            printLinef(COL_DIM, "File: %s", wgFiles[sel]);

            if (parseWGConfFile(path.c_str(), p)) {
                strncpy(p.wg_conffile, wgFiles[sel], sizeof(p.wg_conffile) - 1);
                printLine("Parsed OK.", COL_OK);
                printLinef(COL_DIM, "Endpoint: %s", p.wg_endpoint);
                printLinef(COL_DIM, "Addr:     %s", p.wg_addr);
                delay(1200);
                return true;
            } else {
                printLine("Parse failed!", COL_ERR);
                printLine("Missing PrivateKey or Endpoint.", COL_DIM);
                printLine("Press Fn+M for manual entry,", COL_DIM);
                printLine("or any key to retry.", COL_DIM);
                // Wait for Fn+M or any other key to redraw
                Keyboard_Class::KeysState st2 = waitKey();
                if (isFn(st2)) {
                    for (auto ch : st2.word)
                        if (ch == 'm' || ch == 'M') return false;
                }
                drawWGPicker(wgFiles, fileCount, sel, scroll);
            }
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  WIFI SETUP
// ═══════════════════════════════════════════════════════════════════════════════
void runWifiSetup() {
    drawTitle("WiFi Setup");
    String ssid, pass;
    bool loaded = loadWifiCreds(ssid, pass);

    if (loaded) {
        printLinef(COL_DIM, "Saved: %s", ssid.c_str());
        if (!readYN("Use saved WiFi?")) loaded = false;
    }

    if (!loaded) {
        ssid = readInput("SSID");
        pass = readInput("Password", true);
        if (readYN("Save WiFi?")) saveWifiCreds(ssid.c_str(), pass.c_str());
    }

    strncpy(g_ssid,     ssid.c_str(), sizeof(g_ssid)     - 1);
    strncpy(g_wifiPass, pass.c_str(), sizeof(g_wifiPass) - 1);

    printLine("Connecting...", COL_DIM);
    WiFi.begin(g_ssid, g_wifiPass);
    int tries = 0;
    while (WiFi.status() != WL_CONNECTED && tries < 40) {
        vTaskDelay(500 / portTICK_PERIOD_MS);
        M5Cardputer.Display.print('.');
        tries++;
    }
    printLine("", COL_FG);
    if (WiFi.status() != WL_CONNECTED) {
        printLine("WiFi FAILED!", COL_ERR);
        printLine("Continuing anyway...", COL_DIM);
        delay(1500);
    } else {
        printLine("WiFi connected.", COL_OK);
        delay(600);
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  PROFILE LIST SCREEN
// ═══════════════════════════════════════════════════════════════════════════════
void drawProfileList() {
    int dispW   = M5Cardputer.Display.width();
    int dispH   = M5Cardputer.Display.height();
    int titleH  = LINE_H + 5;
    int hintH   = LINE_H + 2;
    int visRows = (dispH - titleH - hintH) / LINE_H;

    M5Cardputer.Display.fillScreen(COL_BG);

    M5Cardputer.Display.fillRect(0, 0, dispW, LINE_H + 2, COL_TITLE);
    M5Cardputer.Display.setTextColor(COL_BG, COL_TITLE);
    M5Cardputer.Display.setCursor(2, 1);
    M5Cardputer.Display.print("SSH Profiles");
    M5Cardputer.Display.setTextColor(COL_FG, COL_BG);

    M5Cardputer.Display.fillRect(0, dispH - hintH, dispW, hintH, COL_HINT_BG);
    M5Cardputer.Display.setTextColor(COL_DIM, COL_HINT_BG);
    M5Cardputer.Display.setCursor(2, dispH - LINE_H);
    M5Cardputer.Display.print("N:New E:Edit D:Del Enter:Connect");
    M5Cardputer.Display.setTextColor(COL_FG, COL_BG);

    if (profileCount == 0) {
        M5Cardputer.Display.setCursor(4, titleH + 8);
        M5Cardputer.Display.setTextColor(COL_DIM, COL_BG);
        M5Cardputer.Display.println("No profiles yet.");
        M5Cardputer.Display.println("Press Fn+N to create one.");
        M5Cardputer.Display.setTextColor(COL_FG, COL_BG);
        return;
    }

    int scroll = 0;
    if (selectedIdx >= visRows) scroll = selectedIdx - visRows + 1;

    for (int i = 0; i < visRows && (i + scroll) < profileCount; i++) {
        int pi  = i + scroll;
        int y   = titleH + i * LINE_H;
        bool hi = (pi == selectedIdx);

        if (hi) {
            M5Cardputer.Display.fillRect(0, y, dispW, LINE_H, COL_SEL_BG);
            M5Cardputer.Display.setTextColor(COL_SEL_FG, COL_SEL_BG);
        } else {
            M5Cardputer.Display.setTextColor(COL_FG, COL_BG);
        }
        M5Cardputer.Display.setCursor(4, y + 1);
        M5Cardputer.Display.print(profiles[pi].name);

        if (profiles[pi].useWG) {
            M5Cardputer.Display.setTextColor(TFT_YELLOW, hi ? COL_SEL_BG : COL_BG);
            M5Cardputer.Display.setCursor(dispW - 22, y + 1);
            M5Cardputer.Display.print("WG");
        }
        M5Cardputer.Display.setTextColor(COL_FG, COL_BG);
    }
}

void runProfileList() {
    selectedIdx = 0;
    while (true) {
        drawProfileList();
        Keyboard_Class::KeysState st = waitKey();
        bool fn = isFn(st);

        if (fn) {
            for (auto ch : st.word) {
                if      (ch == 'w' || ch == 'W') { if (selectedIdx > 0) selectedIdx--; }
                else if (ch == 's' || ch == 'S') { if (selectedIdx < profileCount - 1) selectedIdx++; }
                else if (ch == 'n' || ch == 'N') { runProfileEdit(-1); }
                else if (ch == 'e' || ch == 'E') { if (profileCount > 0) runProfileEdit(selectedIdx); }
                else if (ch == 'd' || ch == 'D') {
                    if (profileCount > 0) {
                        drawTitle("Delete Profile");
                        printLinef(COL_ERR, "Delete '%s'?", profiles[selectedIdx].name);
                        if (readYN("Confirm")) deleteProfile(selectedIdx);
                    }
                }
            }
        } else {
            if (st.enter && profileCount > 0) runConnect(selectedIdx);
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  PROFILE EDIT / CREATE   (idx == -1 → new)
// ═══════════════════════════════════════════════════════════════════════════════
void runProfileEdit(int idx) {
    bool isNew = (idx < 0);
    Profile p;
    if (isNew) memset(&p, 0, sizeof(p));
    else       p = profiles[idx];

    drawTitle(isNew ? "New Profile" : "Edit Profile");

    // ── Basic SSH fields ──────────────────────────────────────────────────────
    {
        String v = readInput("Name");
        if (v.isEmpty() && isNew) { printLine("Cancelled.", COL_DIM); delay(800); return; }
        if (!v.isEmpty()) strncpy(p.name, v.c_str(), sizeof(p.name) - 1);
    }
    { String v = readInput("Host/IP");        if (!v.isEmpty()) strncpy(p.host, v.c_str(), sizeof(p.host) - 1); }
    { String v = readInput("SSH User");       if (!v.isEmpty()) strncpy(p.user, v.c_str(), sizeof(p.user) - 1); }
    { String v = readInput("SSH Pass", true); if (!v.isEmpty()) strncpy(p.pass, v.c_str(), sizeof(p.pass) - 1); }

    // ── WireGuard ─────────────────────────────────────────────────────────────
    p.useWG = readYN("Use WireGuard?");

    if (p.useWG) {
        // Show the file picker. Returns false only if user presses Fn+M.
        bool fromFile = pickWGConfig(p);

        if (!fromFile) {
            // Manual entry fallback
            drawTitle(isNew ? "New Profile" : "Edit Profile");
            printLine("--- WireGuard (manual) ---", COL_TITLE);
            { String v = readInput("Private Key");         if (!v.isEmpty()) strncpy(p.wg_privkey,  v.c_str(), sizeof(p.wg_privkey)  - 1); }
            { String v = readInput("Tunnel IP (/prefix)"); if (!v.isEmpty()) strncpy(p.wg_addr,     v.c_str(), sizeof(p.wg_addr)     - 1); }
            { String v = readInput("Peer Public Key");     if (!v.isEmpty()) strncpy(p.wg_pubkey,   v.c_str(), sizeof(p.wg_pubkey)   - 1); }
            { String v = readInput("Endpoint (ip:port)");  if (!v.isEmpty()) strncpy(p.wg_endpoint, v.c_str(), sizeof(p.wg_endpoint) - 1); }
            p.wg_conffile[0] = '\0';
        }
    }

    // ── Save ──────────────────────────────────────────────────────────────────
    if (readYN("Save profile?")) {
        saveProfile(p);
        if (isNew) {
            if (profileCount < MAX_PROFILES) {
                profiles[profileCount++] = p;
                selectedIdx = profileCount - 1;
            }
        } else {
            if (strcmp(profiles[idx].name, p.name) != 0)
                SD.remove(profilePath(profiles[idx].name).c_str());
            profiles[idx] = p;
        }
        printLine("Saved!", COL_OK);
        delay(600);
    } else {
        printLine("Discarded.", COL_DIM);
        delay(600);
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
//  CONNECT
// ═══════════════════════════════════════════════════════════════════════════════
void runConnect(int idx) {
    const Profile& p = profiles[idx];
    drawTitle(p.name);
    printLinef(COL_DIM, "Host: %s", p.host);

    if (p.useWG) {
        if (wgActive) { printLine("Stopping prev WG...", COL_DIM); wgDisconnect(); }
        wgConnect(p);
        if (!wgActive) { printLine("WG failed.", COL_ERR); delay(2000); return; }
    }

    printLine("Connecting SSH...", COL_DIM);
    ssh_session sess = sshConnect(p.host, p.user);
    if (!sess) {
        printLine("SSH connect failed.", COL_ERR);
        if (p.useWG) wgDisconnect();
        delay(2000); return;
    }

    if (!sshAuth(sess, p.pass)) {
        printLine("SSH auth failed.", COL_ERR);
        ssh_disconnect(sess); ssh_free(sess);
        if (p.useWG) wgDisconnect();
        delay(2000); return;
    }

    ssh_channel ch = sshOpenShell(sess);
    if (!ch) {
        printLine("Shell failed.", COL_ERR);
        ssh_disconnect(sess); ssh_free(sess);
        if (p.useWG) wgDisconnect();
        delay(2000); return;
    }

    drawTitle(p.name);
    printLine("[Fn+X=logout Fn+C=^C Fn+E=ESC Fn+WASD=arrows]", COL_DIM);
    termCursorY = M5Cardputer.Display.getCursorY();

    runSSHTerminal(sess, ch);

    ssh_channel_close(ch); ssh_channel_free(ch);
    ssh_disconnect(sess);  ssh_free(sess);
    if (p.useWG) wgDisconnect();

    drawTitle(p.name);
    printLine("[Session ended. Any key to return.]", COL_DIM);
    waitKey();
}


// ═══════════════════════════════════════════════════════════════════════════════
//  WIREGUARD
// ═══════════════════════════════════════════════════════════════════════════════
void wgConnect(const Profile& p) {
    printLine("Starting WireGuard...", COL_DIM);

    IPAddress tunIP;
    String addrStr = String(p.wg_addr);
    int slash = addrStr.indexOf('/');
    if (slash >= 0) addrStr = addrStr.substring(0, slash);
    if (!tunIP.fromString(addrStr)) { printLine("Bad WG tunnel IP!", COL_ERR); return; }

    String ep    = String(p.wg_endpoint);
    int colon    = ep.lastIndexOf(':');
    if (colon < 0) { printLine("Bad WG endpoint!", COL_ERR); return; }
    String epHost = ep.substring(0, colon);
    int    epPort = ep.substring(colon + 1).toInt();

    configTime(0, 0, "pool.ntp.org", "time.google.com");
    delay(1000);

    wg.begin(tunIP, p.wg_privkey, epHost.c_str(), p.wg_pubkey, epPort);
    wgActive = true;
    printLine("WireGuard up.", COL_OK);
    delay(500);
}

void wgDisconnect() {
    wgActive = false;
    printLine("WireGuard stopped.", COL_DIM);
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SSH HELPERS
// ═══════════════════════════════════════════════════════════════════════════════
ssh_session sshConnect(const char* host, const char* user) {
    ssh_session s = ssh_new();
    if (!s) return nullptr;
    int verb = SSH_LOG_NOLOG;
    ssh_options_set(s, SSH_OPTIONS_HOST,          host);
    ssh_options_set(s, SSH_OPTIONS_USER,          user);
    ssh_options_set(s, SSH_OPTIONS_LOG_VERBOSITY, &verb);
    if (ssh_connect(s) != SSH_OK) {
        Serial.printf("SSH err: %s\n", ssh_get_error(s));
        ssh_free(s); return nullptr;
    }
    return s;
}

bool sshAuth(ssh_session s, const char* pass) {
    return ssh_userauth_password(s, nullptr, pass) == SSH_AUTH_SUCCESS;
}

ssh_channel sshOpenShell(ssh_session s) {
    ssh_channel ch = ssh_channel_new(s);
    if (!ch) return nullptr;
    if (ssh_channel_open_session(ch) != SSH_OK) { ssh_channel_free(ch); return nullptr; }
    if (ssh_channel_request_pty(ch)  != SSH_OK) { ssh_channel_close(ch); ssh_channel_free(ch); return nullptr; }
    if (ssh_channel_request_shell(ch)!= SSH_OK) { ssh_channel_close(ch); ssh_channel_free(ch); return nullptr; }
    return ch;
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SSH TERMINAL
// ═══════════════════════════════════════════════════════════════════════════════
void runSSHTerminal(ssh_session sess, ssh_channel ch) {
    String cmdBuf = "> ";
    M5Cardputer.Display.print(cmdBuf);
    termCursorY = M5Cardputer.Display.getCursorY();

    while (true) {
        vTaskDelay(10 / portTICK_PERIOD_MS);
        M5Cardputer.update();

        if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
            unsigned long now = millis();
            if (now - lastKeyMs >= DEBOUNCE_MS) {
                lastKeyMs = now;
                Keyboard_Class::KeysState st = M5Cardputer.Keyboard.keysState();
                bool fn = isFn(st);

                if (fn) {
                    for (auto c : st.word) {
                        char ctrl = 0;
                        switch (c) {
                            case 'c': case 'C': ctrl = 0x03; break;
                            case 'x': case 'X': ctrl = 0x04; break;
                            case 'z': case 'Z': ctrl = 0x1A; break;
                            case 'l': case 'L': ctrl = 0x0C; break;
                            case 'e': case 'E': ctrl = 0x1B; break;
                            case 'w': case 'W': { const char s[] = "\x1b[A"; ssh_channel_write(ch, s, 3); break; }
                            case 's': case 'S': { const char s[] = "\x1b[B"; ssh_channel_write(ch, s, 3); break; }
                            case 'a': case 'A': { const char s[] = "\x1b[D"; ssh_channel_write(ch, s, 3); break; }
                            case 'd': case 'D': { const char s[] = "\x1b[C"; ssh_channel_write(ch, s, 3); break; }
                            default: break;
                        }
                        if (ctrl) ssh_channel_write(ch, &ctrl, 1);
                    }
                } else {
                    for (auto c : st.word) {
                        cmdBuf += c;
                        M5Cardputer.Display.print(c);
                        termCursorY = M5Cardputer.Display.getCursorY();
                    }
                    if (st.del && cmdBuf.length() > 2) {
                        cmdBuf.remove(cmdBuf.length() - 1);
                        int cx = M5Cardputer.Display.getCursorX() - 6;
                        int cy = M5Cardputer.Display.getCursorY();
                        M5Cardputer.Display.setCursor(cx, cy);
                        M5Cardputer.Display.print(' ');
                        M5Cardputer.Display.setCursor(cx, cy);
                        termCursorY = cy;
                    }
                    if (st.enter) {
                        String cmd = (cmdBuf.length() > 2)
                            ? cmdBuf.substring(2) + "\r\n" : String("\r\n");
                        ssh_channel_write(ch, cmd.c_str(), cmd.length());
                        cmdBuf = "> ";
                        M5Cardputer.Display.println();
                        termCursorY = M5Cardputer.Display.getCursorY();
                    }
                }
            }
        }

        if (termCursorY > M5Cardputer.Display.height() - LINE_H) scrollUp();

        char buf[256];
        int n = ssh_channel_read_nonblocking(ch, buf, sizeof(buf), 0);
        if (n > 0) {
            bool inEsc = false;
            for (int i = 0; i < n; i++) {
                char c = buf[i];
                if (inEsc) {
                    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) inEsc = false;
                    continue;
                }
                if (c == 0x1B) { inEsc = true;  continue; }
                if (c == '\r') continue;
                if (M5Cardputer.Display.getCursorY() >
                    M5Cardputer.Display.height() - LINE_H) scrollUp();
                M5Cardputer.Display.write(c);
                termCursorY = M5Cardputer.Display.getCursorY();
            }
        }
        if (n < 0 || ssh_channel_is_closed(ch)) break;
    }
}
