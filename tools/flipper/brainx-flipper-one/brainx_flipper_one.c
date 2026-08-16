/*
 * BraiNIX One -- Flipper Zero as a Bluetooth keyboard for a machine in
 * recoveryOS, driven from a workstation over the Flipper's USB CLI.
 *
 * WHY THIS SHAPE
 *
 * The first version had it backwards: USB HID to the target, BLE *serial* back
 * to the workstation. That put the fragile link on the side that had a
 * perfectly good wired option, and the wired link on the side that could have
 * been wireless. It also picked a Flipper-specific BLE service whose
 * characteristics demand an encrypted link CoreBluetooth will not negotiate on
 * its own -- writes returned success, the connection dropped after ~2 s, and
 * `rx` stayed at 0 while everything *looked* fine.
 *
 * This version inverts it:
 *
 *   BLE HID   -> the target. A standard profile. macOS pairs with it the same
 *                way it pairs with a Magic Keyboard, and recoveryOS supports
 *                Bluetooth keyboards because people use them.
 *   USB CDC   -> the workstation. The Flipper CLI, completely reliable all
 *                along. The app registers a `braix` command, so the
 *                workstation types by writing to a serial port.
 *
 * Both links are now the boring, well-trodden option for their side.
 *
 * NO ARM BUTTON, AND THAT IS DELIBERATE
 *
 * The previous version required a physical arm press because anything arriving
 * over BLE was typed into a root shell -- a BLE peer must not be able to arm
 * itself. Here the *only* input path is the USB CLI, which already requires
 * physical possession of the cable, and BLE is output-only: nothing can inject
 * keystrokes over it. The guard has nothing left to guard, and it was the thing
 * blocking unattended operation.
 */

#include <furi.h>
#include <furi_hal_bt.h>
#include <furi_hal_usb_hid.h> /* HID_ASCII_TO_KEY and the keycode table */
#include <gui/gui.h>
#include <input/input.h>
#include <bt/bt_service/bt.h>
#include <extra_profiles/hid_profile.h>
#include <cli/cli.h>
#include <toolbox/cli/cli_registry.h>
#include <toolbox/pipe.h>

#define TAG "BraiNIXOne"

/* Per-keystroke delay. recoveryOS Terminal drops characters typed faster than
 * this, and a dropped character inside a path fails as "no such file" -- which
 * reads like a staging problem rather than a typing one. Measured working at
 * 12 ms over USB HID; BLE HID adds latency, so this is not tightened. */
#define KEY_DELAY_MS 12

/* Advertised as "BraiNIX..." so it is identifiable in the target's Bluetooth
 * list. The profile requires a prefix shorter than 8 characters. */
#define DEVICE_NAME_PREFIX "BraiNIX"

typedef struct {
    FuriMutex* mutex;
    Bt* bt;
    CliRegistry* cli;
    FuriHalBleProfileBase* profile;

    bool profile_started;
    bool ble_connected;
    uint32_t lines_typed;
    char last_line[48];

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
    if(!app->profile_started) {
        /* Visible because a NULL from bt_profile_start used to be invisible,
         * and looked identical to a working app. */
        canvas_draw_str(canvas, 2, 24, "HID: PROFILE FAILED");
    } else {
        canvas_draw_str(canvas, 2, 24, app->ble_connected ? "HID: linked" : "HID: pair me");
    }
    canvas_draw_str(canvas, 2, 34, "USB CLI: braix ...");

    char stats[40];
    snprintf(stats, sizeof(stats), "lines typed: %lu", (unsigned long)app->lines_typed);
    canvas_draw_str(canvas, 2, 46, stats);
    canvas_draw_str(canvas, 2, 58, app->last_line[0] ? app->last_line : "back: exit");

    furi_mutex_release(app->mutex);
}

static void input_callback(InputEvent* event, void* context) {
    BraiNIXOne* app = context;
    if(event->type == InputTypeShort && event->key == InputKeyBack) app->running = false;
}

static void bt_status_callback(BtStatus status, void* context) {
    BraiNIXOne* app = context;
    /* Service-thread callback: record only, let the UI thread repaint. */
    app->ble_connected = (status == BtStatusConnected);
}

/* ---------------------------------------------------------------- typing -- */

static void type_text(BraiNIXOne* app, const char* text, size_t length, bool press_enter) {
    for(size_t i = 0; i < length; i++) {
        uint16_t key = HID_ASCII_TO_KEY(text[i]);
        if(key == HID_KEYBOARD_NONE) continue;
        ble_profile_hid_kb_press(app->profile, key);
        furi_delay_ms(KEY_DELAY_MS / 2);
        ble_profile_hid_kb_release(app->profile, key);
        furi_delay_ms(KEY_DELAY_MS / 2);
    }
    if(press_enter) {
        ble_profile_hid_kb_press(app->profile, HID_KEYBOARD_RETURN);
        furi_delay_ms(KEY_DELAY_MS);
        ble_profile_hid_kb_release(app->profile, HID_KEYBOARD_RETURN);
    }

    furi_check(furi_mutex_acquire(app->mutex, FuriWaitForever) == FuriStatusOk);
    app->lines_typed++;
    size_t shown = length < sizeof(app->last_line) - 1 ? length : sizeof(app->last_line) - 1;
    memcpy(app->last_line, text, shown);
    app->last_line[shown] = '\0';
    furi_mutex_release(app->mutex);

    view_port_update(app->viewport);
}

/* ------------------------------------------------------------------- cli -- */

/* `braix type <text>`  -- type <text> and press Return
 * `braix raw <text>`   -- type <text> with no Return
 * `braix status`       -- report link state, so the workstation can check
 *                        without a camera pointed at the Flipper.
 *
 * Reporting back matters: the previous design could not distinguish "sent"
 * from "delivered", and three wrong conclusions came from that gap. */
static void braix_cli_callback(PipeSide* pipe, FuriString* args, void* context) {
    BraiNIXOne* app = context;

    FuriString* verb = furi_string_alloc();
    size_t space = furi_string_search_char(args, ' ');
    if(space == FURI_STRING_FAILURE) {
        furi_string_set(verb, args);
        furi_string_reset(args);
    } else {
        furi_string_set_n(verb, args, 0, space);
        furi_string_right(args, space + 1);
    }

    char reply[160];
    if(furi_string_equal_str(verb, "status")) {
        snprintf(
            reply,
            sizeof(reply),
            "profile=%s link=%s typed=%lu\r\n",
            app->profile_started ? "up" : "FAILED",
            app->ble_connected ? "connected" : "not-connected",
            (unsigned long)app->lines_typed);
    } else if(!app->profile_started) {
        snprintf(reply, sizeof(reply), "error: HID profile did not start\r\n");
    } else if(!app->ble_connected) {
        /* Refuse rather than type into nothing. A command that vanishes is
         * worse than one that says it went nowhere. */
        snprintf(reply, sizeof(reply), "error: not connected -- pair the target first\r\n");
    } else if(furi_string_equal_str(verb, "type") || furi_string_equal_str(verb, "raw")) {
        bool enter = furi_string_equal_str(verb, "type");
        const char* text = furi_string_get_cstr(args);
        size_t length = strlen(text);
        type_text(app, text, length, enter);
        snprintf(
            reply,
            sizeof(reply),
            "ok: typed %u chars%s\r\n",
            (unsigned)length,
            enter ? " + Return" : "");
    } else {
        snprintf(reply, sizeof(reply), "usage: braix type|raw <text> | braix status\r\n");
    }

    pipe_send(pipe, reply, strlen(reply));
    furi_string_free(verb);
}

/* ------------------------------------------------------------------- app -- */

int32_t brainx_flipper_one_app(void* p) {
    UNUSED(p);

    BraiNIXOne* app = malloc(sizeof(BraiNIXOne));
    memset(app, 0, sizeof(BraiNIXOne));
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->running = true;

    app->viewport = view_port_alloc();
    view_port_draw_callback_set(app->viewport, draw_callback, app);
    view_port_input_callback_set(app->viewport, input_callback, app);
    app->gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(app->gui, app->viewport, GuiLayerFullscreen);

    /* USB is deliberately left alone: it stays CDC so the CLI keeps working.
     * That is the whole point of this design. */

    app->bt = furi_record_open(RECORD_BT);
    bt_set_status_changed_callback(app->bt, bt_status_callback, app);
    bt_disconnect(app->bt);
    furi_delay_ms(200); /* the disconnect restarts core2; do not race it */

    BleProfileHidParams params = {
        .device_name_prefix = DEVICE_NAME_PREFIX,
        .mac_xor = 0x0001,
    };
    app->profile = bt_profile_start(app->bt, ble_profile_hid, &params);
    app->profile_started = (app->profile != NULL);
    if(app->profile) {
        furi_hal_bt_start_advertising();
    } else {
        FURI_LOG_E(TAG, "BLE HID profile failed to start");
    }

    app->cli = furi_record_open(RECORD_CLI);
    cli_registry_add_command(app->cli, "braix", CliCommandFlagDefault, braix_cli_callback, app);

    while(app->running) {
        furi_delay_ms(200);
        view_port_update(app->viewport);
    }

    cli_registry_delete_command(app->cli, "braix");
    furi_record_close(RECORD_CLI);

    bt_set_status_changed_callback(app->bt, NULL, NULL);
    bt_profile_restore_default(app->bt);
    furi_record_close(RECORD_BT);

    gui_remove_view_port(app->gui, app->viewport);
    furi_record_close(RECORD_GUI);
    view_port_free(app->viewport);
    furi_mutex_free(app->mutex);
    free(app);
    return 0;
}
