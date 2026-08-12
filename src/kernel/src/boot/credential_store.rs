//! Persistent credential store: loads the authentication credentials from the
//! data disk at boot (or provisions the defaults and writes them on a blank
//! disk), holds them in a kernel global, and persists password changes.
//!
//! This is the bridge between the pure `auth` TCB core (verification + on-disk
//! serialization) and the virtio-blk driver (sector I/O). It keeps credential
//! handling entirely inside the kernel: a compromised userspace process cannot
//! read or forge the store.
//!
//! Single-core boot and IF-masked (non-preemptible) userspace mean the globals
//! here are never accessed concurrently.
//!
//! Allowlist: `src/kernel/src/boot/` — mutable static for the kernel-global
//! credential store and device handle.
#![allow(unsafe_code)]

use crate::arch::virtio_blk::{VirtioBlockDevice, SECTOR_SIZE_IN_BYTES};
use crate::auth::{
    CredentialStore, UserIdentity, CREDENTIAL_BLOCK_SIZE_IN_BYTES, SALT_LENGTH_IN_BYTES,
};
use crate::boot::logger::BootStepLogger;
use crate::hardware_security::csprng::generate_random_bytes;

/// Disk sector holding the credential block (front of the data disk).
const CREDENTIAL_SECTOR: u64 = 0;

static mut CREDENTIAL_BLOCK_DEVICE: Option<VirtioBlockDevice> = None;
static mut KERNEL_CREDENTIAL_STORE: Option<CredentialStore> = None;

/// Loads the credential store from `device` sector 0, or — if the sector does
/// not hold a valid block — provisions root/jbrahy with the default password
/// and writes it. Stores the device handle and the store in kernel globals.
pub fn initialize_credential_store(
    device: VirtioBlockDevice,
    boot_step_logger: &mut BootStepLogger,
) {
    // SAFETY: single-core boot; first and only writer of these globals.
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(CREDENTIAL_BLOCK_DEVICE),
            Some(device),
        );
    }

    let mut block = [0u8; SECTOR_SIZE_IN_BYTES];
    if !device.read_sector(CREDENTIAL_SECTOR, &mut block) {
        boot_step_logger.fail("Credential store", "sector read failed");
        return;
    }

    match CredentialStore::deserialize_from_block(&block) {
        Some(store) => {
            store_credential_store(store);
            boot_step_logger.ok("Credential store loaded from disk (persisted)");
        }
        None => {
            let store = provision_default_store();
            persist_store(&device, &store, boot_step_logger);
            store_credential_store(store);
            boot_step_logger.ok("Credential store provisioned (root/jbrahy, must change)");
        }
    }
}

/// Verifies a login against the global store. Returns `(user, must_change)`.
pub fn verify_login(name: &[u8], password: &[u8]) -> Option<(UserIdentity, bool)> {
    // SAFETY: single-core, non-preemptible; read-only access to the global.
    let store = unsafe { (*core::ptr::addr_of!(KERNEL_CREDENTIAL_STORE)).as_ref()? };
    let user = store.verify_login(name, password)?;
    let must_change = store.credential_for(user).must_change_password();
    Some((user, must_change))
}

/// Changes `user`'s password (fresh CSPRNG salt), clears the force-change flag,
/// and persists the updated store to disk. Returns false if no store/device.
pub fn change_password(user: UserIdentity, new_password: &[u8]) -> bool {
    // SAFETY: single-core, non-preemptible; exclusive access to the globals.
    unsafe {
        let store = match (*core::ptr::addr_of_mut!(KERNEL_CREDENTIAL_STORE)).as_mut() {
            Some(store) => store,
            None => return false,
        };
        let salt = random_salt();
        store
            .credential_for_mut(user)
            .change_password(salt, new_password);
        let device = match (*core::ptr::addr_of!(CREDENTIAL_BLOCK_DEVICE)).as_ref() {
            Some(device) => device,
            None => return false,
        };
        device.write_sector(CREDENTIAL_SECTOR, &store.serialize_to_block())
    }
}

fn store_credential_store(store: CredentialStore) {
    // SAFETY: single-core boot; sole writer.
    unsafe {
        core::ptr::write(
            core::ptr::addr_of_mut!(KERNEL_CREDENTIAL_STORE),
            Some(store),
        );
    }
}

fn provision_default_store() -> CredentialStore {
    CredentialStore::with_default_passwords(random_salt(), random_salt())
}

fn persist_store(
    device: &VirtioBlockDevice,
    store: &CredentialStore,
    boot_step_logger: &mut BootStepLogger,
) {
    if !device.write_sector(CREDENTIAL_SECTOR, &store.serialize_to_block()) {
        boot_step_logger.fail("Credential store", "initial persist failed");
    }
}

fn random_salt() -> [u8; SALT_LENGTH_IN_BYTES] {
    let mut salt = [0u8; SALT_LENGTH_IN_BYTES];
    generate_random_bytes(&mut salt);
    salt
}

// CREDENTIAL_BLOCK_SIZE_IN_BYTES must equal the sector size for the block to
// occupy exactly one sector.
const _: () = assert!(CREDENTIAL_BLOCK_SIZE_IN_BYTES == SECTOR_SIZE_IN_BYTES);
