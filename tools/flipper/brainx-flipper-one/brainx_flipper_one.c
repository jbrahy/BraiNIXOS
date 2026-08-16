/*
 * BraiNIX One -- a Flipper Zero bridge from BLE to USB HID.
 *
 * WHY THIS EXISTS
 *
 * Apple Silicon recovery-mode bring-up means typing long `bputil` and `kmutil`
 * invocations into a shell with no history, no paste, and no way to read the
 * result back. Two of this project's failures were transcription errors, and
 * every one of them was invisible because no output was ever captured. See
 * docs/operations/BRINGUP_PLAN.md.
 *
 * THE ONE-PORT PROBLEM, AND WHY BLE
 *
 * The Flipper has a single USB port. Plugged into the target as a keyboard, it
 * is not connected to the workstation, so a BadUSB script has to be decided in
 * advance and cannot be corrected once the target's state is known. BLE and
 * USB are independent peripherals here: this app is a USB HID keyboard to the
 * target and a BLE serial endpoint to the workstation at the same time. Lines
 * arrive over BLE and are typed into whatever has focus.
 *
 * WHAT IT IS NOT
 *
 * One-directional with respect to the target. It cannot read the target's
 * screen and cannot hold the power button for One True Recovery. It removes
 * transcription error and makes the command set correctable at the moment of
 * use. It does not replace m1n1 as the feedback loop.
 *
 * SAFETY
 *
 * Whatever arrives over BLE is typed into a root shell. Typing is therefore
 * OFF until it is armed on the device -- a connection alone cannot type
 * anything. The armed state is shown on screen, and leaving the app disarms.
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

/* Bytes buffered between the BLE callback and the typing worker. Larger than
 * any single command we send; a full buffer drops input rather than blocking
 * the BLE stack, and says so on screen. */
#define RX_BUFFER_SIZE 2048

/* Per-keystroke delay. Recovery-mode Terminal drops characters typed faster
 * than this, and a dropped character in a path fails as "no such file" --
 * which reads like a staging problem rather than a typing one. */
#define KEY_DELAY_MS 12

typedef struct {
    FuriMutex* mutex;
    FuriStreamBuffer* rx;
    Bt* bt;
    FuriHalBleProfileBase* profile;

    bool armed;
    bool ble_connected;
    uint32_t lines_typed;
    uint32_t bytes_received;
    bool overflowed;
    char last_line[64];

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
    canvas_draw_str(canvas, 2, 24, app->ble_connected ? "BLE: connected" : "BLE: advertising");
    canvas_draw_str(canvas, 2, 34, app->armed ? "TYPING: ARMED" : "TYPING: disarmed (OK)");

    char stats[48];
    snprintf(
        stats,
        sizeof(stats),
        "rx %lu b   lines %lu%s",
        (unsigned long)app->bytes_received,
        (unsigned long)app->lines_typed,
        app->overflowed ? " OVF" : "");
    canvas_draw_str(canvas, 2, 46, stats);

    if(app->last_line[0]) {
        canvas_draw_str(canvas, 2, 58, app->last_line);
    } else {
        canvas_draw_str(canvas, 2, 58, "back: exit");
    }

    furi_mutex_release(app->mutex);
}

static void input_callback(InputEvent* event, void* context) {
    BraiNIXOne* app = context;
    if(event->type != InputTypeShort) return;

    if(event->key == InputKeyBack) {
        app->running = false;
    } else if(event->key == InputKeyOk) {
        /* Arming is deliberately a physical act. A BLE peer cannot arm itself,
         * so a stray connection can never type into a root shell. */
        furi_check(furi_mutex_acquire(app->mutex, FuriWaitForever) == FuriStatusOk);
        app->armed = !app->armed;
        furi_mutex_release(app->mutex);
        view_port_update(app->viewport);
    }
}

/* ------------------------------------------------------------------- ble -- */

static uint16_t serial_rx_callback(SerialServiceEvent event, void* context) {
    BraiNIXOne* app = context;

    if(event.event == SerialServiceEventTypeDataReceived) {
        /* This runs on the BLE stack's own thread. The first version of this
         * function took the UI mutex and called view_port_update() from here,
         * which crashed the firmware on the first launch. Nothing but the
         * stream buffer -- which is explicitly thread-safe -- happens here now;
         * counters and repaints belong to the main loop. */
        size_t written = furi_stream_buffer_send(app->rx, event.data.buffer, event.data.size, 0);
        if(written < event.data.size) app->overflowed = true;
        app->bytes_received += written;
    }

    return furi_stream_buffer_spaces_available(app->rx);
}

static void bt_status_callback(BtStatus status, void* context) {
    BraiNIXOne* app = context;
    /* Also a service-thread callback: record and let the main loop repaint. */
    app->ble_connected = (status == BtStatusConnected);
}

/* ----------------------------------------------------------------- typing -- */

static void type_char(char character) {
    uint16_t key = HID_ASCII_TO_KEY(character);
    if(key == HID_KEYBOARD_NONE) return;
    furi_hal_hid_kb_press(key);
    furi_delay_ms(KEY_DELAY_MS / 2);
    furi_hal_hid_kb_release(key);
    furi_delay_ms(KEY_DELAY_MS / 2);
}

static void type_line(BraiNIXOne* app, const char* line, size_t length) {
    for(size_t i = 0; i < length; i++) {
        type_char(line[i]);
    }
    furi_hal_hid_kb_press(HID_KEYBOARD_RETURN);
    furi_delay_ms(KEY_DELAY_MS);
    furi_hal_hid_kb_release(HID_KEYBOARD_RETURN);

    furi_check(furi_mutex_acquire(app->mutex, FuriWaitForever) == FuriStatusOk);
    app->lines_typed++;
    size_t shown = length < sizeof(app->last_line) - 1 ? length : sizeof(app->last_line) - 1;
    memcpy(app->last_line, line, shown);
    app->last_line[shown] = '\0';
    furi_mutex_release(app->mutex);

    view_port_update(app->viewport);
}

/* ------------------------------------------------------------------- app -- */

int32_t brainx_flipper_one_app(void* p) {
    UNUSED(p);

    BraiNIXOne* app = malloc(sizeof(BraiNIXOne));
    memset(app, 0, sizeof(BraiNIXOne));
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->rx = furi_stream_buffer_alloc(RX_BUFFER_SIZE, 1);
    app->running = true;

    app->viewport = view_port_alloc();
    view_port_draw_callback_set(app->viewport, draw_callback, app);
    view_port_input_callback_set(app->viewport, input_callback, app);
    app->gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(app->gui, app->viewport, GuiLayerFullscreen);

    /* USB first: the target must see a keyboard even if BLE never connects, so
     * a failure here is visible immediately rather than after pairing. */
    FuriHalUsbInterface* usb_previous = furi_hal_usb_get_config();
    furi_hal_usb_unlock();
    furi_check(furi_hal_usb_set_config(&usb_hid, NULL));

    /* Then BLE, through the Bt SERVICE -- not furi_hal_bt directly.
     *
     * The first version called furi_hal_bt_start_app() while the bt service
     * still owned the radio, and the firmware crashed and rebooted on launch.
     * The service arbitrates the second core; an app that goes around it is
     * racing the owner of the hardware. bt_profile_restore_default() on exit
     * hands the radio back so the phone app works again afterwards. */
    app->bt = furi_record_open(RECORD_BT);
    bt_set_status_changed_callback(app->bt, bt_status_callback, app);
    bt_disconnect(app->bt);
    furi_delay_ms(200); /* the disconnect restarts core2; do not race it */

    app->profile = bt_profile_start(app->bt, ble_profile_serial, NULL);
    if(app->profile) {
        ble_profile_serial_set_event_callback(
            app->profile, RX_BUFFER_SIZE, serial_rx_callback, app);
        furi_hal_bt_start_advertising();
    } else {
        FURI_LOG_E(TAG, "BLE serial profile failed to start");
    }

    /* Assemble whole lines before typing. A command typed in fragments as BLE
     * packets arrive would execute a prefix of itself on any dropped tail. */
    char line[512];
    size_t fill = 0;

    while(app->running) {
        uint8_t byte;
        size_t got = furi_stream_buffer_receive(app->rx, &byte, 1, 100);
        if(got == 0) {
            view_port_update(app->viewport); /* status/counters, from the UI thread */
            continue;
        }

        if(byte == '\n' || byte == '\r') {
            if(fill > 0) {
                bool armed;
                furi_check(furi_mutex_acquire(app->mutex, FuriWaitForever) == FuriStatusOk);
                armed = app->armed;
                furi_mutex_release(app->mutex);

                if(armed) type_line(app, line, fill);
                fill = 0;
            }
        } else if(fill < sizeof(line) - 1) {
            line[fill++] = (char)byte;
        } else {
            /* Over-long line: drop it whole rather than type a truncation. */
            fill = 0;
            furi_check(furi_mutex_acquire(app->mutex, FuriWaitForever) == FuriStatusOk);
            app->overflowed = true;
            furi_mutex_release(app->mutex);
        }
    }

    bt_set_status_changed_callback(app->bt, NULL, NULL);
    bt_profile_restore_default(app->bt);
    furi_record_close(RECORD_BT);
    furi_hal_usb_set_config(usb_previous, NULL);

    gui_remove_view_port(app->gui, app->viewport);
    furi_record_close(RECORD_GUI);
    view_port_free(app->viewport);
    furi_stream_buffer_free(app->rx);
    furi_mutex_free(app->mutex);
    free(app);
    return 0;
}
