//! Device lookup, against the target's own device tree.
//!
//! `mac14-12-j474s-adt.bin` was read out of the deployment machine over m1n1's
//! proxy. Two of the addresses it yields are known independently, from m1n1's
//! own boot log on the same machine, which is what makes this a check rather
//! than a restatement.

use brainix_kernel::aarch64_devices::translated_reg;

static REAL_ADT: &[u8] = include_bytes!("../../adt/tests/fixtures/mac14-12-j474s-adt.bin");

/// m1n1 printed "Primary WDT register @ 0x29e2c4000" on this machine.
#[test]
fn the_watchdog_resolves_to_the_address_m1n1_reported() {
    assert_eq!(
        translated_reg(REAL_ADT, b"/arm-io/wdt", 0),
        Some(0x2_9E2C_4000),
        "what gets written here is a machine reset; a wrong address is not a \
         wasted cycle"
    );
}

/// m1n1 printed "Initialized dockchannel UART at 0x29e528000".
#[test]
fn the_dockchannel_uart_resolves_to_the_address_m1n1_reported() {
    assert_eq!(
        translated_reg(REAL_ADT, b"/arm-io/dockchannel-uart", 0),
        Some(0x2_9E52_8000)
    );
}

/// The translation is the point, not a formality.
#[test]
fn the_translated_address_differs_from_the_raw_one() {
    let translated = translated_reg(REAL_ADT, b"/arm-io/wdt", 0).unwrap();
    // The tree states these `reg` values without the /arm-io window applied.
    assert_ne!(
        translated, 0x9E2C_4000,
        "returning the raw address is the bug this function exists to prevent: \
         it is a valid-looking physical address pointing at the wrong device"
    );
    assert_eq!(
        translated - 0x9E2C_4000,
        0x2_0000_0000,
        "the /arm-io window"
    );
}

#[test]
fn a_missing_node_denies_rather_than_guessing() {
    assert_eq!(
        translated_reg(REAL_ADT, b"/arm-io/not-a-real-device", 0),
        None
    );
    assert_eq!(translated_reg(REAL_ADT, b"/nowhere", 0), None);
}

#[test]
fn a_blob_that_does_not_parse_denies() {
    assert_eq!(translated_reg(&[], b"/arm-io/wdt", 0), None);
    assert_eq!(translated_reg(&[0xFF; 64], b"/arm-io/wdt", 0), None);
}
