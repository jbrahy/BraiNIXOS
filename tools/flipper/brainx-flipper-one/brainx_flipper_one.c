/*
 * BraiNIX One -- Flipper Zero as a USB keyboard for a machine in recoveryOS,
 * driven over BLE from a workstation.
 *
 * WHY THIS SHAPE, AFTER TWO THAT DID NOT WORK
 *
 * v1 was USB HID to the target and BLE serial back to the workstation, and it
 * appeared to fail. v2 inverted it: BLE HID to the target, USB CLI back. v2
 * cannot be built at all. Every `ble_profile_hid_*` entry point and every
 * `ble_svc_hid_*` entry point is marked `-` in the firmware's api_symbols.csv,
 * which is the firmware saying it does not export BLE HID to external
 * applications. That is a policy in the API table, not a defect to route
 * around, and it is exactly what `err_04 Missing imports` was reporting.
 *
 * By contrast `usb_hid`, every `furi_hal_hid_*` function, and the whole BLE
 * serial profile are marked `+`. So v1's topology was the only buildable one
 * all along:
 *
 *   USB HID     -> the target. The same path BadUSB uses, and the one link in
 *                  this rig that has never once failed.
 *   BLE serial  -> the workstation: commands in, status out.
 *
 * THE BUG THAT MADE v1 LOOK BROKEN
 *
 * The serial service is flow-controlled by the *return value* of its event
 * callback -- it is the number of further bytes the application will accept.
 * Return zero and the credit is zero, so a peer's writes are accepted by
 * CoreBluetooth, acknowledged as successful, and then never delivered. That is
 * precisely what "the write returned success and rx stayed at 0" looked like,
 * and it is invisible from the workstation end. `serial_service.h` types the
 * callback as returning uint16_t and says nothing about what the number means.
 *
 * Every return path in ble_rx_callback below therefore yields a non-zero
 * credit. Zero is a stall, never "no opinion".
 *
 * WHAT ARMING IS FOR
 *
 * Everything that arrives over BLE is typed into a root shell in recoveryOS.
 * The OK button toggles arming and the state is on screen. It defaults to
 * ARMED because the machine this drives is usually unattended -- the button is
 * a kill switch someone standing at the Flipper can reach, not a gate.
 */

#include <furi.h>
#include <furi_hal_bt.h>
#include <furi_hal_usb.h>
#include <furi_hal_usb_hid.h>
#include <gui/gui.h>
#include <input/input.h>
#include <bt/bt_service/bt.h>
#include <profiles/serial_profile.h>

#define TAG "BraiNIXOne"

/* Per-keystroke delay. recoveryOS Terminal drops characters typed faster than
 * this, and a character dropped inside a path fails as "no such file", which
 * reads like a staging problem rather than a typing one. */
#define KEY_DELAY_MS 12

#define LINE_MAX     192
#define QUEUE_DEPTH  8
#define LAST_LINE_MAX 40

typedef struct {
    char text[LINE_MAX];
} BraixLine;

typedef struct {
    FuriMutex* mutex;
    Bt* bt;
    FuriHalBleProfileBase* profile;
    FuriHalUsbInterface* usb_prev;
    FuriMessageQueue* queue;

    /* Touched only by the BLE stack thread, so unguarded on purpose. */
    char partial[LINE_MAX];
    size_t partial_len;

    /* Shared with the UI and app threads; hold the mutex. */
    bool profile_started;
    bool ble_connected;
    bool armed;
    uint32_t lines_typed;
    uint32_t rx_bytes;
    char last_line[LAST_LINE_MAX];

    volatile bool running;
    ViewPort* viewport;
    Gui* gui;
} BraiNIXOne;

/* ------------------------------------------------------------------ view -- */

static void draw_callback(Canvas* canvas, void* context) {
    BraiNIXOne* app = context;
    furi_check(furi_mutex_acquire(app->mutex, FuriWaitForever) == FuriStatusOk);

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 10, "BraiNIX One");

    canvas_set_font(canvas, FontSecondary);

    char line[48];
    /* Both links, always, because the whole point of this app is that a silent
     * failure on either one used to be indistinguishable from working. */
    snprintf(
        line,
        sizeof(line),
        "BLE %s   USB %s",
        !app->profile_started ? "FAILED" : (app->ble_connected ? "linked" : "waiting"),
        furi_hal_hid_is_connected() ? "linked" : "waiting");
    canvas_draw_str(canvas, 2, 23, line);

    snprintf(
        line,
        sizeof(line),
        "%s  rx %lu  typed %lu",
        app->armed ? "ARMED" : "disarmed",
        (unsigned long)app->rx_bytes,
        (unsigned long)app->lines_typed);
    canvas_draw_str(canvas, 2, 35, line);

    canvas_draw_str(canvas, 2, 47, app->last_line[0] ? app->last_line : "-");
    canvas_draw_str(canvas, 2, 61, "ok: arm/disarm   back: exit");

    furi_mutex_release(app->mutex);
}

static void input_callback(InputEvent* event, void* context) {
    BraiNIXOne* app = context;
    if(event->type != InputTypeShort) return;

    if(event->key == InputKeyBack) {
        app->running = false;
    } else if(event->key == InputKeyOk) {
        furi_check(furi_mutex_acquire(app->mutex, FuriWaitForever) == FuriStatusOk);
        app->armed = !app->armed;
        furi_mutex_release(app->mutex);
        view_port_update(app->viewport);
    }
}

static void bt_status_callback(BtStatus status, void* context) {
    BraiNIXOne* app = context;
    /* Service-thread callback: record only, let the UI thread repaint. */
    app->ble_connected = (status == BtStatusConnected);
}

/* -------------------------------------------------------------------- ble -- */

static void reply(BraiNIXOne* app, const char* text) {
    if(!app->profile) return;
    ble_profile_serial_tx(app->profile, (uint8_t*)text, (uint16_t)strlen(text));
}

/* Returns the number of further bytes this app will accept. NEVER zero -- see
 * the header comment; zero silently wedges the link. */
static uint16_t ble_rx_callback(SerialServiceEvent event, void* context) {
    BraiNIXOne* app = context;

    if(event.event != SerialServiceEventTypeDataReceived) {
        return LINE_MAX;
    }

    for(uint16_t i = 0; i < event.data.size; i++) {
        char c = (char)event.data.buffer[i];
        if(c == '\r') continue;

        if(c != '\n') {
            if(app->partial_len < LINE_MAX - 1) {
                app->partial[app->partial_len++] = c;
            } else {
                /* Overlong line: discard the whole thing. Typing a truncated
                 * command into a root shell is worse than typing nothing. */
                FURI_LOG_W(TAG, "line over %d chars, discarded", LINE_MAX - 1);
                app->partial_len = 0;
            }
            continue;
        }

        app->partial[app->partial_len] = '\0';
        if(app->partial_len > 0) {
            BraixLine line;
            memcpy(line.text, app->partial, app->partial_len + 1);
            /* Non-blocking. Typing takes ~12 ms per character, and the BLE
             * stack thread must not wait on it. A full queue drops the line
             * and logs, rather than stalling the radio. */
            if(furi_message_queue_put(app->queue, &line, 0) != FuriStatusOk) {
                FURI_LOG_W(TAG, "queue full, dropped: %s", line.text);
            }
        }
        app->partial_len = 0;
    }

    furi_check(furi_mutex_acquire(app->mutex, FuriWaitForever) == FuriStatusOk);
    app->rx_bytes += event.data.size;
    furi_mutex_release(app->mutex);
    view_port_update(app->viewport);

    return LINE_MAX;
}

/* ---------------------------------------------------------------- typing -- */

static void tap(uint16_t key) {
    furi_hal_hid_kb_press(key);
    furi_delay_ms(KEY_DELAY_MS / 2);
    furi_hal_hid_kb_release(key);
    furi_delay_ms(KEY_DELAY_MS / 2);
}

static void type_text(BraiNIXOne* app, const char* text, bool press_enter) {
    for(const char* p = text; *p; p++) {
        uint16_t key = HID_ASCII_TO_KEY(*p);
        if(key == HID_KEYBOARD_NONE) continue;
        tap(key);
    }
    if(press_enter) tap(HID_KEYBOARD_RETURN);

    furi_check(furi_mutex_acquire(app->mutex, FuriWaitForever) == FuriStatusOk);
    app->lines_typed++;
    strncpy(app->last_line, text, LAST_LINE_MAX - 1);
    app->last_line[LAST_LINE_MAX - 1] = '\0';
    furi_mutex_release(app->mutex);

    view_port_update(app->viewport);
}

/* The keys a recovery session actually needs: the startup picker, a Terminal
 * that has to be brought to the front, and a shell. Not a full keymap. */
static const struct {
    const char* name;
    uint16_t key;
} named_keys[] = {
    {"enter", HID_KEYBOARD_RETURN},
    {"tab", HID_KEYBOARD_TAB},
    {"esc", HID_KEYBOARD_ESCAPE},
    {"space", HID_KEYBOARD_SPACEBAR},
    {"up", HID_KEYBOARD_UP_ARROW},
    {"down", HID_KEYBOARD_DOWN_ARROW},
    {"left", HID_KEYBOARD_LEFT_ARROW},
    {"right", HID_KEYBOARD_RIGHT_ARROW},
    {"ctrl-c", HID_KEYBOARD_C | KEY_MOD_LEFT_CTRL},
    {"ctrl-d", HID_KEYBOARD_D | KEY_MOD_LEFT_CTRL},
    {"cmd-tab", HID_KEYBOARD_TAB | KEY_MOD_LEFT_GUI},
};

/* ------------------------------------------------------------- commands -- */

static void handle_line(BraiNIXOne* app, const char* line) {
    const char* rest = strchr(line, ' ');
    size_t verb_len = rest ? (size_t)(rest - line) : strlen(line);
    if(rest) rest++;

    char out[96];

    if(verb_len == 6 && !strncmp(line, "status", 6)) {
        snprintf(
            out,
            sizeof(out),
            "ble=%s usb=%s %s typed=%lu rx=%lu\r\n",
            app->ble_connected ? "linked" : "waiting",
            furi_hal_hid_is_connected() ? "linked" : "waiting",
            app->armed ? "armed" : "disarmed",
            (unsigned long)app->lines_typed,
            (unsigned long)app->rx_bytes);
        reply(app, out);
        return;
    }

    if(!app->armed) {
        /* Refuse loudly. A command that vanishes is worse than one that says
         * it went nowhere -- three wrong conclusions in this project came from
         * exactly that gap. */
        reply(app, "error: disarmed, press OK on the Flipper\r\n");
        return;
    }

    if(!furi_hal_hid_is_connected()) {
        reply(app, "error: USB HID not enumerated by the target\r\n");
        return;
    }

    if(verb_len == 4 && !strncmp(line, "type", 4) && rest) {
        type_text(app, rest, true);
        snprintf(out, sizeof(out), "ok: typed %u chars + Return\r\n", (unsigned)strlen(rest));
        reply(app, out);
        return;
    }

    if(verb_len == 3 && !strncmp(line, "raw", 3) && rest) {
        type_text(app, rest, false);
        snprintf(out, sizeof(out), "ok: typed %u chars\r\n", (unsigned)strlen(rest));
        reply(app, out);
        return;
    }

    if(verb_len == 3 && !strncmp(line, "key", 3) && rest) {
        for(size_t i = 0; i < COUNT_OF(named_keys); i++) {
            if(!strcmp(rest, named_keys[i].name)) {
                tap(named_keys[i].key);
                snprintf(out, sizeof(out), "ok: %s\r\n", rest);
                reply(app, out);
                return;
            }
        }
        reply(app, "error: unknown key name\r\n");
        return;
    }

    reply(app, "usage: type <text> | raw <text> | key <name> | status\r\n");
}

/* ------------------------------------------------------------------- app -- */

int32_t brainx_flipper_one_app(void* p) {
    UNUSED(p);

    BraiNIXOne* app = malloc(sizeof(BraiNIXOne));
    memset(app, 0, sizeof(BraiNIXOne));
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->queue = furi_message_queue_alloc(QUEUE_DEPTH, sizeof(BraixLine));
    app->running = true;
    app->armed = true;

    app->viewport = view_port_alloc();
    view_port_draw_callback_set(app->viewport, draw_callback, app);
    view_port_input_callback_set(app->viewport, input_callback, app);
    app->gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(app->gui, app->viewport, GuiLayerFullscreen);

    /* Take over USB as a keyboard. The previous config is saved rather than
     * assumed to be CDC, so exiting restores whatever was actually there. */
    app->usb_prev = furi_hal_usb_get_config();
    if(furi_hal_usb_is_locked() || !furi_hal_usb_set_config(&usb_hid, NULL)) {
        FURI_LOG_E(TAG, "could not switch USB to HID");
    }

    app->bt = furi_record_open(RECORD_BT);
    bt_set_status_changed_callback(app->bt, bt_status_callback, app);
    bt_disconnect(app->bt);
    furi_delay_ms(200); /* the disconnect restarts core2; do not race it */

    app->profile = bt_profile_start(app->bt, ble_profile_serial, NULL);
    app->profile_started = (app->profile != NULL);
    if(app->profile) {
        /* Take the serial stream away from the RPC layer, which otherwise
         * consumes it, and register for the raw bytes. The buffer size here is
         * the initial flow-control credit. */
        ble_profile_serial_set_rpc_active(app->profile, false);
        ble_profile_serial_set_event_callback(app->profile, LINE_MAX, ble_rx_callback, app);
        /* Explicit, because "I don't see it in the Bluetooth list" was a real
         * failure mode and this call is idempotent. */
        furi_hal_bt_start_advertising();
    } else {
        FURI_LOG_E(TAG, "BLE serial profile failed to start");
    }

    BraixLine line;
    while(app->running) {
        if(furi_message_queue_get(app->queue, &line, 100) == FuriStatusOk) {
            handle_line(app, line.text);
        }
        view_port_update(app->viewport);
    }

    bt_set_status_changed_callback(app->bt, NULL, NULL);
    bt_profile_restore_default(app->bt);
    furi_record_close(RECORD_BT);

    furi_hal_hid_kb_release_all();
    if(app->usb_prev) furi_hal_usb_set_config(app->usb_prev, NULL);

    gui_remove_view_port(app->gui, app->viewport);
    furi_record_close(RECORD_GUI);
    view_port_free(app->viewport);
    furi_message_queue_free(app->queue);
    furi_mutex_free(app->mutex);
    free(app);
    return 0;
}
