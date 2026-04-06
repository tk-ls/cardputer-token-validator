#include <M5Cardputer.h>
#include <M5GFX.h>
#include <MFRC522_I2C.h>
#include "mbedtls/md.h"

// ── Hardware ─────────────────────────────────────────────────────────────────
#define RFID_I2C_ADDR  0x28
#define START_PAGE     4
#define PAGE_COUNT     8          // pages 4-11: HMAC
#define ID_LEN_PAGE    12         // page 12: identifier length byte
#define ID_DATA_PAGE   13         // pages 13-15: identifier string (12 bytes)
#define ID_MAX_LEN     12

MFRC522_I2C rfid(RFID_I2C_ADDR, -1);

// ── Secret ───────────────────────────────────────────────────────────────────
static const char* HMAC_KEY = "a_secret_key_replace_me123";

// ── Card types ────────────────────────────────────────────────────────────────
#define TYPE_COUNT 3
static const char*    TYPE_NAMES[] = { "TOKEN", "RED COKE", "BLACK COKE" };
static const uint8_t  TYPE_SALT[]  = { 0, 1, 2 };
static const uint16_t TYPE_BG[]    = { 0x0320, 0x6000, 0x0000 };

// ── Display + sprite ──────────────────────────────────────────────────────────
static M5GFX&   D = M5Cardputer.Display;
static M5Canvas sprite(&M5Cardputer.Display);

static int SW() { return (int)D.width();  }
static int SH() { return (int)D.height(); }
#define CX (SW() / 2)

// ── Palette ───────────────────────────────────────────────────────────────────
#define C_BG     0x0000
#define C_FG     0xFFFF
#define C_GREEN  0x07E0
#define C_DIM    0x4208
#define C_YELLOW 0xFFE0

// ── Menu layout ───────────────────────────────────────────────────────────────
#define MENU_Y0     38
#define ROW_H       26
#define ROW_INNER_H 24

// ── Key repeat ───────────────────────────────────────────────────────────────
#define KEY_FIRST_MS  500
#define KEY_REPEAT_MS 350

// ── State ────────────────────────────────────────────────────────────────────
enum Mode { MENU, MINT_TYPE, MINT_ENTRY, MINT_SCAN, VERIFY, CLEAR };
static Mode mode        = MENU;
static int  menuSel     = 0;
static int  typeSel     = 0;
static bool headerDrawn = false;

// ── Identifier input buffer ───────────────────────────────────────────────────
static char  identBuf[ID_MAX_LEN + 1] = {};  // working buffer during MINT_ENTRY
static int   identLen = 0;

// ── Key repeat ────────────────────────────────────────────────────────────────
static char     lastKey      = '\0';
static uint32_t keyDownMs    = 0;
static uint32_t lastRepeatMs = 0;

static bool keyTick(char k) {
    uint32_t now = millis();
    if (k == '\0') { lastKey = '\0'; return false; }
    if (k != lastKey) {
        lastKey = k; keyDownMs = lastRepeatMs = now;
        return true;
    }
    if (now - keyDownMs >= KEY_FIRST_MS && now - lastRepeatMs >= KEY_REPEAT_MS) {
        lastRepeatMs = now; return true;
    }
    return false;
}

// Call after every mode transition. Zeroing lastKey alone is not enough:
// if the key is still physically held, the next keyTick call sees it as a
// brand-new press and fires immediately. Keeping lastKey as '\0' but stamping
// keyDownMs = now forces the full KEY_FIRST_MS hold delay before any repeat.
static void resetKeys() {
    lastKey      = '\0';
    keyDownMs    = millis();
    lastRepeatMs = keyDownMs;
}

// ── Crypto ────────────────────────────────────────────────────────────────────
// HMAC input: uid || salt || identifier_bytes
static void calcHMAC(const uint8_t* uid, uint8_t uidLen,
                     uint8_t salt,
                     const char* ident, uint8_t identLenArg,
                     uint8_t out[32]) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, (const uint8_t*)HMAC_KEY, strlen(HMAC_KEY));
    mbedtls_md_hmac_update(&ctx, uid, uidLen);
    mbedtls_md_hmac_update(&ctx, &salt, 1);
    mbedtls_md_hmac_update(&ctx, (const uint8_t*)ident, identLenArg);
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

static bool writeHash(const uint8_t h[32]) {
    for (int i = 0; i < PAGE_COUNT; i++)
        if (rfid.MIFARE_Ultralight_Write(START_PAGE + i, (uint8_t*)&h[i*4], 4) != MFRC522_I2C::STATUS_OK)
            return false;
    return true;
}

static bool readHash(uint8_t out[32]) {
    uint8_t tmp[18];
    for (int i = 0; i < 2; i++) {
        uint8_t sz = sizeof(tmp);
        if (rfid.MIFARE_Read(START_PAGE + i*4, tmp, &sz) != MFRC522_I2C::STATUS_OK)
            return false;
        memcpy(&out[i*16], tmp, 16);
    }
    return true;
}

// Write identifier: 1-byte length in page 12, then up to 12 bytes across pages 13-15
static bool writeIdent(const char* ident, uint8_t len) {
    // Page 12: length byte padded to 4 bytes
    uint8_t lenPage[4] = { len, 0, 0, 0 };
    if (rfid.MIFARE_Ultralight_Write(ID_LEN_PAGE, lenPage, 4) != MFRC522_I2C::STATUS_OK)
        return false;

    // Pages 13-15: 12 bytes of identifier, zero-padded
    uint8_t buf[12] = {};
    memcpy(buf, ident, len);
    for (int i = 0; i < 3; i++)
        if (rfid.MIFARE_Ultralight_Write(ID_DATA_PAGE + i, &buf[i*4], 4) != MFRC522_I2C::STATUS_OK)
            return false;
    return true;
}

// Read identifier into out (null-terminated). Returns false on read error.
static bool readIdent(char out[ID_MAX_LEN + 1]) {
    uint8_t tmp[18];
    uint8_t sz;

    // Read page 12 for length
    sz = sizeof(tmp);
    if (rfid.MIFARE_Read(ID_LEN_PAGE, tmp, &sz) != MFRC522_I2C::STATUS_OK)
        return false;
    uint8_t len = tmp[0];
    if (len > ID_MAX_LEN) len = 0;  // corrupt/missing — treat as empty

    // Read pages 13-15 (one MIFARE_Read gives 16 bytes = 4 pages)
    sz = sizeof(tmp);
    if (rfid.MIFARE_Read(ID_DATA_PAGE, tmp, &sz) != MFRC522_I2C::STATUS_OK)
        return false;

    memcpy(out, tmp, len);
    out[len] = '\0';
    return true;
}

// ── Draw helpers (dual-target) ────────────────────────────────────────────────
static void _greenHeader(LovyanGFX* g, const char* title) {
    int w = (int)g->width();
    g->fillRect(0, 0, w, 32, C_GREEN);
    g->setTextColor(C_BG);
    g->setTextSize(2);
    g->setTextDatum(MC_DATUM);
    g->drawString(title, w / 2, 16);
}

static void _dimFooter(LovyanGFX* g, const char* txt) {
    g->setTextColor(C_DIM);
    g->setTextSize(1);
    g->setTextDatum(MC_DATUM);
    g->drawString(txt, (int)g->width() / 2, (int)g->height() - 8);
}

static void _drawRow(LovyanGFX* g, int idx, bool selected, const char* label) {
    int w = (int)g->width();
    int y = MENU_Y0 + idx * ROW_H;
    g->fillRect(0, y, w, ROW_INNER_H, selected ? C_GREEN : C_BG);
    g->setTextColor(selected ? C_BG : C_FG);
    g->setTextSize(2);
    g->setTextDatum(MC_DATUM);
    g->drawString(label, w / 2, y + 12);
}

static void _renderMenu(LovyanGFX* g) {
    g->fillScreen(C_BG);
    _greenHeader(g, "TOKEN VALIDATOR");
    static const char* items[] = { "MINT", "VERIFY", "CLEAR" };
    for (int i = 0; i < 3; i++) _drawRow(g, i, i == menuSel, items[i]);
    _dimFooter(g, ",/. NAV   ENTER SEL");
}

static void _renderMintType(LovyanGFX* g) {
    g->fillScreen(C_BG);
    _greenHeader(g, "MINT");
    for (int i = 0; i < TYPE_COUNT; i++) _drawRow(g, i, i == typeSel, TYPE_NAMES[i]);
    _dimFooter(g, ",/. NAV   ENTER SEL   ` DEL ESC");
}

// Entry screen: shows typed identifier with a blinking cursor.
// When fullRedraw=false, only repaints the input box strip (no flicker on blink).
static void _renderMintEntry(LovyanGFX* g, bool cursorOn = true, bool fullRedraw = true) {
    int w = (int)g->width();
    int h = (int)g->height();

    if (fullRedraw) {
        g->fillScreen(C_BG);
        _greenHeader(g, "IDENTIFIER");
        _dimFooter(g, "TYPE NAME   ENTER OK   ` DEL ESC");
    }

    // Input box strip — always repainted
    int boxY = 42, boxH = 36;
    // Clear the strip first to avoid ghosting
    g->fillRect(0, boxY - 2, w, boxH + 4, C_BG);
    g->drawRect(8, boxY, w - 16, boxH, C_DIM);

    // Text + cursor
    char display[ID_MAX_LEN + 2] = {};
    memcpy(display, identBuf, identLen);
    if (cursorOn) display[identLen] = '_';

    g->setTextColor(C_FG);
    g->setTextSize(2);
    g->setTextDatum(ML_DATUM);
    g->drawString(display, 14, boxY + boxH / 2);

    // Character counter
    char counter[8];
    snprintf(counter, sizeof(counter), "%d/12", identLen);
    g->setTextColor(C_DIM);
    g->setTextSize(1);
    g->setTextDatum(MR_DATUM);
    g->drawString(counter, w - 10, boxY + boxH / 2);
}

static void _renderScanScreen(LovyanGFX* g, const char* title) {
    int w = (int)g->width();
    int h = (int)g->height();
    g->fillScreen(C_BG);
    _greenHeader(g, title);
    g->setTextColor(C_FG);
    g->setTextSize(2);
    g->setTextDatum(MC_DATUM);
    g->drawString("PRESENT CARD", w / 2, h / 2);
    _dimFooter(g, "` DEL ESC");
}

// ── Horizontal pan transition ─────────────────────────────────────────────────
static void panTo(void (*renderDest)(LovyanGFX*), int direction,
                  const char* scanTitle = nullptr) {
    int w = SW();
    int h = SH();
    sprite.createSprite(w, h);
    if (scanTitle) _renderScanScreen(&sprite, scanTitle);
    else           renderDest(&sprite);

    int steps = 12;
    for (int s = 1; s <= steps; s++) {
        int destX = direction * (w - w * s / steps);
        if (direction > 0) {
            if (destX > 0) D.fillRect(0, 0, destX, h, C_BG);
        } else {
            int trailing = destX + w;
            if (trailing < w) D.fillRect(trailing, 0, w - trailing, h, C_BG);
        }
        sprite.pushSprite(destX, 0);
    }
    sprite.pushSprite(0, 0);
    sprite.deleteSprite();
}

static void panForward(void (*renderDest)(LovyanGFX*), const char* scanTitle = nullptr) {
    panTo(renderDest, +1, scanTitle);
}
static void panBack(void (*renderDest)(LovyanGFX*)) {
    panTo(renderDest, -1);
}

// Wrapper for panTo with entry screen (needs cursorOn=true default)
static void _renderMintEntryForSprite(LovyanGFX* g) {
    _renderMintEntry(g, true);
}

// ── Direct draws ──────────────────────────────────────────────────────────────
static void drawMenu()      { _renderMenu(&D);     headerDrawn = false; }
static void drawMintType()  { _renderMintType(&D); headerDrawn = false; }
static void drawMintEntry() { _renderMintEntry(&D, true); headerDrawn = false; }
static void drawScanScreen(const char* title) { _renderScanScreen(&D, title); headerDrawn = true; }

// ── Highlight animation ───────────────────────────────────────────────────────
static void animateHighlight(int fromIdx, int toIdx,
                             const char** labels, int count) {
    int w       = SW();
    int fromY   = MENU_Y0 + fromIdx * ROW_H;
    int toY     = MENU_Y0 + toIdx   * ROW_H;
    int totalDy = toY - fromY;
    int steps   = 8;
    for (int s = 1; s <= steps; s++) {
        int barY     = fromY + totalDy * s / steps;
        int dirtyTop = min(fromY, toY);
        int dirtyBot = max(fromY, toY) + ROW_INNER_H;
        D.fillRect(0, dirtyTop, w, dirtyBot - dirtyTop, C_BG);
        D.fillRect(0, barY, w, ROW_INNER_H, C_GREEN);
        for (int i = 0; i < count; i++) {
            int ry = MENU_Y0 + i * ROW_H;
            if (ry + ROW_INNER_H <= dirtyTop || ry >= dirtyBot) continue;
            D.setTextColor(ry == barY ? C_BG : C_FG);
            D.setTextSize(2);
            D.setTextDatum(MC_DATUM);
            D.drawString(labels[i], w / 2, ry + 12);
        }
    }
}

// ── Result screen ─────────────────────────────────────────────────────────────
static void showFullResult(uint16_t bg, uint16_t fg,
                           const char* line1, const char* line2 = nullptr) {
    D.fillScreen(bg);
    D.setTextColor(fg);
    D.setTextDatum(MC_DATUM);
    int cx = CX, cy = SH() / 2;
    if (line2) {
        D.setTextSize(4); D.drawString(line1, cx, cy - 22);
        D.setTextSize(2); D.drawString(line2, cx, cy + 22);
    } else {
        D.setTextSize(4); D.drawString(line1, cx, cy);
    }
    // Non-blocking wait — keep polling so keyboard state stays fresh
    uint32_t t0 = millis();
    while (millis() - t0 < 1800) { M5Cardputer.update(); delay(10); }
    headerDrawn = false;
    resetKeys();  // discard any keys pressed during the result display
}

// ── Mode handlers ─────────────────────────────────────────────────────────────
static void handleMintScan() {
    if (!headerDrawn) drawScanScreen(TYPE_NAMES[typeSel]);
    if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) return;

    uint8_t hash[32];
    calcHMAC(rfid.uid.uidByte, rfid.uid.size,
             TYPE_SALT[typeSel],
             identBuf, (uint8_t)identLen,
             hash);

    bool ok = writeHash(hash);
    if (ok) ok = writeIdent(identBuf, (uint8_t)identLen);

    if (ok) showFullResult(TYPE_BG[typeSel], C_FG, "MINTED", typeSel == 0 ? nullptr : (identBuf[0] ? identBuf : "OK"));
    else    showFullResult(C_YELLOW, C_BG, "FAILED");
    rfid.PICC_HaltA();
}

static void handleVerify() {
    if (!headerDrawn) drawScanScreen("VERIFY");
    if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) return;

    uint8_t stored[32];
    if (!readHash(stored)) {
        showFullResult(C_YELLOW, C_BG, "READ ERR");
        rfid.PICC_HaltA(); return;
    }

    // Read identifier from card first
    char cardIdent[ID_MAX_LEN + 1] = {};
    bool identOk = readIdent(cardIdent);
    uint8_t cardIdentLen = identOk ? (uint8_t)strlen(cardIdent) : 0;

    // Try all three salts, including identifier in HMAC
    int matched = -1;
    for (int t = 0; t < TYPE_COUNT; t++) {
        uint8_t expected[32];
        calcHMAC(rfid.uid.uidByte, rfid.uid.size,
                 TYPE_SALT[t],
                 cardIdent, cardIdentLen,
                 expected);
        if (memcmp(stored, expected, 32) == 0) { matched = t; break; }
    }

    if (matched >= 0) {
        // TOKEN has no identifier — show type name. Coke types show the stored identifier.
        const char* displayName = (matched == 0) ? TYPE_NAMES[matched]
                                : (cardIdentLen > 0) ? cardIdent : "UNKNOWN";
        showFullResult(TYPE_BG[matched], C_FG, "VALID", displayName);
    } else {
        showFullResult(C_YELLOW, C_BG, "INVALID");
    }
    rfid.PICC_HaltA();
}

static void handleClear() {
    if (!headerDrawn) drawScanScreen("CLEAR");
    if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) return;

    static const uint8_t Z[4] = {};
    bool ok = true;
    // Clear HMAC pages (4-11)
    for (int i = 0; i < PAGE_COUNT && ok; i++)
        ok = (rfid.MIFARE_Ultralight_Write(START_PAGE + i, (uint8_t*)Z, 4) == MFRC522_I2C::STATUS_OK);
    // Clear identifier pages (12-15)
    for (int i = 0; i < 4 && ok; i++)
        ok = (rfid.MIFARE_Ultralight_Write(ID_LEN_PAGE + i, (uint8_t*)Z, 4) == MFRC522_I2C::STATUS_OK);

    if (ok) showFullResult(0x0841, C_FG, "CLEARED");
    else    showFullResult(C_YELLOW, C_BG, "FAILED");
    rfid.PICC_HaltA();
}

// ── Entry screen cursor blink ─────────────────────────────────────────────────
static uint32_t lastBlinkMs  = 0;
static bool     cursorVisible = true;
#define BLINK_MS 500

static void handleMintEntry() {
    uint32_t now = millis();
    if (now - lastBlinkMs >= BLINK_MS) {
        lastBlinkMs   = now;
        cursorVisible = !cursorVisible;
        _renderMintEntry(&D, cursorVisible, false);  // dirty strip only — no flicker
    }
}

// ── Setup / Loop ──────────────────────────────────────────────────────────────
void setup() {
    auto cfg = M5.config();
    M5Cardputer.begin(cfg, true);
    D.setRotation(1);
    Wire.begin(2, 1);
    rfid.PCD_Init();
    drawMenu();
}

void loop() {
    M5Cardputer.update();

    bool kp = M5Cardputer.Keyboard.isPressed();
    char k = '\0';
    if (kp) {
        if      (M5Cardputer.Keyboard.isKeyPressed('`') ||
                 M5Cardputer.Keyboard.isKeyPressed(KEY_BACKSPACE)) k = '`';
        else if (M5Cardputer.Keyboard.isKeyPressed(',') ||
                 M5Cardputer.Keyboard.isKeyPressed(';'))           k = ',';
        else if (M5Cardputer.Keyboard.isKeyPressed('.') ||
                 M5Cardputer.Keyboard.isKeyPressed('/'))           k = '.';
        else if (M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER))     k = 13;
    }

    // ── MINT_ENTRY: character input handled separately (not via keyTick) ──────
    if (mode == MINT_ENTRY) {
        bool transitioned = false;

        if (kp && M5Cardputer.Keyboard.isKeyPressed(KEY_BACKSPACE)) {
            // Backspace: delete last character with key repeat
            if (keyTick('`')) {
                if (identLen > 0) {
                    identBuf[--identLen] = '\0';
                    lastBlinkMs = millis(); cursorVisible = true;
                    _renderMintEntry(&D, true, false);
                }
            }
        } else if (kp && M5Cardputer.Keyboard.isKeyPressed('`')) {
            // Bare backtick = go back to MINT_TYPE
            if (keyTick('`')) {
                mode = MINT_TYPE;
                panBack(_renderMintType);
                headerDrawn = false;
                resetKeys();
                transitioned = true;
            }
        } else if (kp && M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)) {
            // Enter confirms — only if buffer non-empty
            if (keyTick(13) && identLen > 0) {
                mode = MINT_SCAN;
                panForward(nullptr, TYPE_NAMES[typeSel]);
                headerDrawn = true;
                resetKeys();
                transitioned = true;
            }
        } else {
            // Printable character — append uppercased if room
            if (kp) {
                auto& kb = M5Cardputer.Keyboard;
                for (char c = 32; c < 127; c++) {
                    if (kb.isKeyPressed(c)) {
                        if (keyTick(c) && identLen < ID_MAX_LEN) {
                            identBuf[identLen++] = toupper((unsigned char)c);
                            identBuf[identLen]   = '\0';
                            lastBlinkMs = millis(); cursorVisible = true;
                            _renderMintEntry(&D, true, false);
                        }
                        break;
                    }
                }
            } else {
                keyTick('\0');
            }
        }

        // Only blink cursor if we did not just transition away
        if (!transitioned) handleMintEntry();
        return;
    }

    if (keyTick(k)) {
        static const char* menuItems[] = { "MINT", "VERIFY", "CLEAR" };

        switch (mode) {
            case MENU:
                if (k == ',') {
                    int prev = menuSel;
                    menuSel = (menuSel - 1 + 3) % 3;
                    animateHighlight(prev, menuSel, menuItems, 3);
                } else if (k == '.') {
                    int prev = menuSel;
                    menuSel = (menuSel + 1) % 3;
                    animateHighlight(prev, menuSel, menuItems, 3);
                } else if (k == 13) {
                    if (menuSel == 0) {
                        mode = MINT_TYPE;
                        panForward(_renderMintType);
                        headerDrawn = false;
                    } else if (menuSel == 1) {
                        mode = VERIFY;
                        panForward(nullptr, "VERIFY");
                        headerDrawn = true;
                    } else if (menuSel == 2) {
                        mode = CLEAR;
                        panForward(nullptr, "CLEAR");
                        headerDrawn = true;
                    }
                    resetKeys();
                }
                break;

            case MINT_TYPE:
                if (k == ',') {
                    int prev = typeSel;
                    typeSel = (typeSel - 1 + TYPE_COUNT) % TYPE_COUNT;
                    animateHighlight(prev, typeSel, TYPE_NAMES, TYPE_COUNT);
                } else if (k == '.') {
                    int prev = typeSel;
                    typeSel = (typeSel + 1) % TYPE_COUNT;
                    animateHighlight(prev, typeSel, TYPE_NAMES, TYPE_COUNT);
                } else if (k == 13) {
                    memset(identBuf, 0, sizeof(identBuf));
                    identLen = 0;
                    if (typeSel == 0) {
                        // TOKEN: no identifier, go straight to scan
                        mode = MINT_SCAN;
                        panForward(nullptr, TYPE_NAMES[typeSel]);
                        headerDrawn = true;
                    } else {
                        // COKE types: collect identifier first
                        lastBlinkMs = millis(); cursorVisible = true;
                        mode = MINT_ENTRY;
                        panForward(_renderMintEntryForSprite);
                        headerDrawn = false;
                    }
                    resetKeys();
                } else if (k == '`') {
                    mode = MENU;
                    panBack(_renderMenu);
                    headerDrawn = false;
                    resetKeys();
                }
                break;

            // ROOT CAUSE FIX: MINT_SCAN was missing from this switch entirely.
            // Backtick had nowhere to go — keyTick consumed it, hit default: break,
            // and the key was silently swallowed every loop iteration.
            case MINT_SCAN:
                if (k == '`') {
                    if (typeSel == 0) {
                        // TOKEN came straight from MINT_TYPE, go back there
                        mode = MINT_TYPE;
                        panBack(_renderMintType);
                        headerDrawn = false;
                    } else {
                        // COKE came via MINT_ENTRY, go back there
                        mode = MINT_ENTRY;
                        lastBlinkMs = millis(); cursorVisible = true;
                        panBack(_renderMintEntryForSprite);
                        headerDrawn = false;
                    }
                    resetKeys();
                }
                break;

            case VERIFY:
            case CLEAR:
                if (k == '`') {
                    mode = MENU;
                    panBack(_renderMenu);
                    headerDrawn = false;
                    resetKeys();
                }
                break;

            default: break;
        }
    }

    switch (mode) {
        case MINT_SCAN: handleMintScan(); break;
        case VERIFY:    handleVerify();   break;
        case CLEAR:     handleClear();    break;
        default: break;
    }
}
