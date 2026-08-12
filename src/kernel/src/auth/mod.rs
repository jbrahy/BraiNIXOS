//! Credential store and login verification — the authentication TCB.
//!
//! Password verification lives in the kernel, not in the shell, so a
//! compromised userspace process cannot bypass the login gate (INV-AUTH-001:
//! no ambient authority — authority to act as a user is proven by knowing the
//! password, checked here in the trusted base).
//!
//! The system ships with two users, `root` and `jbrahy`, both with the initial
//! password `brainxos` and the `must_change_password` flag set, so the first
//! login is forced to choose a new password.
//!
//! Storage model: passwords are never stored in cleartext. Each credential
//! holds a random salt and `SHA-256(salt || password)`. Verification is a
//! constant-time comparison of the recomputed hash. Salts are supplied by the
//! caller (the kernel passes CSPRNG bytes; tests pass fixed bytes) so this core
//! is pure and host-testable.
//!
//! Persistence: the on-disk credential store (devd-disk milestone) serializes
//! [`CredentialStore`] and protects it with a kernel-held MAC so an untrusted
//! disk driver cannot forge credentials. This module owns only the in-memory
//! representation and the verification logic.

use sha2::{Digest, Sha256};

/// Length in bytes of a password salt.
pub const SALT_LENGTH_IN_BYTES: usize = 16;

/// Length in bytes of a stored password hash (SHA-256 digest).
pub const PASSWORD_HASH_LENGTH_IN_BYTES: usize = 32;

/// The initial password assigned to both shipped users. Must be changed on
/// first login (the `must_change_password` flag is set at construction).
pub const INITIAL_DEFAULT_PASSWORD: &[u8] = b"brainxos";

/// The two users provisioned at first boot.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum UserIdentity {
    /// The superuser.
    Root,
    /// The primary interactive user.
    Jbrahy,
}

impl UserIdentity {
    /// Resolves a login name (raw bytes typed at the prompt) to a user.
    ///
    /// Returns `None` for any name that is not a provisioned user, so the
    /// login gate reveals nothing about which names exist.
    pub fn from_login_name(name: &[u8]) -> Option<UserIdentity> {
        match name {
            b"root" => Some(UserIdentity::Root),
            b"jbrahy" => Some(UserIdentity::Jbrahy),
            _ => None,
        }
    }

    /// The canonical login name for this user.
    pub fn login_name(self) -> &'static [u8] {
        match self {
            UserIdentity::Root => b"root",
            UserIdentity::Jbrahy => b"jbrahy",
        }
    }
}

/// One user's stored credential: a salt, the salted password hash, and whether
/// the password must be changed before the account can be used.
#[derive(Copy, Clone, Debug)]
pub struct Credential {
    salt: [u8; SALT_LENGTH_IN_BYTES],
    password_hash: [u8; PASSWORD_HASH_LENGTH_IN_BYTES],
    must_change_password: bool,
}

impl Credential {
    /// Builds a credential for `password` salted with `salt`, with the
    /// force-change flag set (used for the shipped default password).
    pub fn new_requiring_change(salt: [u8; SALT_LENGTH_IN_BYTES], password: &[u8]) -> Self {
        Self {
            salt,
            password_hash: hash_password_with_salt(&salt, password),
            must_change_password: true,
        }
    }

    /// True if `password` matches this credential. Constant-time over the hash
    /// comparison so a timing side channel cannot reveal how many bytes matched.
    pub fn verify_password(&self, password: &[u8]) -> bool {
        let candidate = hash_password_with_salt(&self.salt, password);
        constant_time_bytes_equal(&candidate, &self.password_hash)
    }

    /// Replaces the password with `new_password` (salted with `new_salt`) and
    /// clears the force-change flag. The caller supplies a fresh random salt.
    pub fn change_password(&mut self, new_salt: [u8; SALT_LENGTH_IN_BYTES], new_password: &[u8]) {
        self.salt = new_salt;
        self.password_hash = hash_password_with_salt(&new_salt, new_password);
        self.must_change_password = false;
    }

    /// True if the user must change their password before the account is usable.
    pub fn must_change_password(&self) -> bool {
        self.must_change_password
    }

    /// Test-only access to the stored hash, for asserting salt independence.
    #[cfg(test)]
    pub(crate) fn verify_hash_for_test(&self) -> [u8; PASSWORD_HASH_LENGTH_IN_BYTES] {
        self.password_hash
    }
}

/// The complete set of provisioned users and their credentials.
#[derive(Copy, Clone, Debug)]
pub struct CredentialStore {
    root_credential: Credential,
    jbrahy_credential: Credential,
}

impl CredentialStore {
    /// Provisions both users with the [`INITIAL_DEFAULT_PASSWORD`] and the
    /// force-change flag set. Each user gets its own salt (the kernel passes
    /// independent CSPRNG draws).
    pub fn with_default_passwords(
        root_salt: [u8; SALT_LENGTH_IN_BYTES],
        jbrahy_salt: [u8; SALT_LENGTH_IN_BYTES],
    ) -> Self {
        Self {
            root_credential: Credential::new_requiring_change(root_salt, INITIAL_DEFAULT_PASSWORD),
            jbrahy_credential: Credential::new_requiring_change(
                jbrahy_salt,
                INITIAL_DEFAULT_PASSWORD,
            ),
        }
    }

    /// Immutable access to a user's credential.
    pub fn credential_for(&self, user: UserIdentity) -> &Credential {
        match user {
            UserIdentity::Root => &self.root_credential,
            UserIdentity::Jbrahy => &self.jbrahy_credential,
        }
    }

    /// Mutable access to a user's credential (for `change_password`).
    pub fn credential_for_mut(&mut self, user: UserIdentity) -> &mut Credential {
        match user {
            UserIdentity::Root => &mut self.root_credential,
            UserIdentity::Jbrahy => &mut self.jbrahy_credential,
        }
    }

    /// Verifies a login attempt. Returns the user on success so the caller can
    /// then check [`Credential::must_change_password`].
    pub fn verify_login(&self, name: &[u8], password: &[u8]) -> Option<UserIdentity> {
        let user = UserIdentity::from_login_name(name)?;
        if self.credential_for(user).verify_password(password) {
            Some(user)
        } else {
            None
        }
    }
}

/// Size of the on-disk credential block (one 512-byte sector).
pub const CREDENTIAL_BLOCK_SIZE_IN_BYTES: usize = 512;

/// Magic identifying a BraiNIX credential block ("BNXC", little-endian).
const CREDENTIAL_BLOCK_MAGIC: u32 = 0x4358_4E42;

/// On-disk format version.
const CREDENTIAL_BLOCK_VERSION: u32 = 1;

// Field offsets within the block.
const OFFSET_MAGIC: usize = 0;
const OFFSET_VERSION: usize = 4;
const OFFSET_ROOT_SALT: usize = 8;
const OFFSET_ROOT_HASH: usize = 24;
const OFFSET_ROOT_FLAG: usize = 56;
const OFFSET_JBRAHY_SALT: usize = 57;
const OFFSET_JBRAHY_HASH: usize = 73;
const OFFSET_JBRAHY_FLAG: usize = 105;
/// Bytes covered by the integrity checksum (everything before it).
const CHECKSUM_COVERAGE_END: usize = 106;
const OFFSET_CHECKSUM: usize = 106;

impl CredentialStore {
    /// Serializes the store into a 512-byte block with a magic, version, and a
    /// SHA-256 integrity checksum over the payload.
    ///
    /// The checksum detects corruption or out-of-band tampering of the disk
    /// image. A keyed MAC (TPM-sealed) replaces it once the disk driver moves
    /// into the untrusted devd-disk server; today the kernel does the I/O.
    pub fn serialize_to_block(&self) -> [u8; CREDENTIAL_BLOCK_SIZE_IN_BYTES] {
        let mut block = [0u8; CREDENTIAL_BLOCK_SIZE_IN_BYTES];
        block[OFFSET_MAGIC..OFFSET_MAGIC + 4]
            .copy_from_slice(&CREDENTIAL_BLOCK_MAGIC.to_le_bytes());
        block[OFFSET_VERSION..OFFSET_VERSION + 4]
            .copy_from_slice(&CREDENTIAL_BLOCK_VERSION.to_le_bytes());
        write_credential_into_block(
            &mut block,
            &self.root_credential,
            OFFSET_ROOT_SALT,
            OFFSET_ROOT_HASH,
            OFFSET_ROOT_FLAG,
        );
        write_credential_into_block(
            &mut block,
            &self.jbrahy_credential,
            OFFSET_JBRAHY_SALT,
            OFFSET_JBRAHY_HASH,
            OFFSET_JBRAHY_FLAG,
        );
        let checksum = sha256_of(&block[..CHECKSUM_COVERAGE_END]);
        block[OFFSET_CHECKSUM..OFFSET_CHECKSUM + 32].copy_from_slice(&checksum);
        block
    }

    /// Parses a 512-byte block, returning the store only if the magic, version,
    /// and integrity checksum all validate.
    pub fn deserialize_from_block(block: &[u8; CREDENTIAL_BLOCK_SIZE_IN_BYTES]) -> Option<Self> {
        if read_u32(block, OFFSET_MAGIC) != CREDENTIAL_BLOCK_MAGIC {
            return None;
        }
        if read_u32(block, OFFSET_VERSION) != CREDENTIAL_BLOCK_VERSION {
            return None;
        }
        let expected_checksum = sha256_of(&block[..CHECKSUM_COVERAGE_END]);
        if !constant_time_bytes_equal(
            &expected_checksum,
            &block[OFFSET_CHECKSUM..OFFSET_CHECKSUM + 32],
        ) {
            return None;
        }
        Some(Self {
            root_credential: read_credential_from_block(
                block,
                OFFSET_ROOT_SALT,
                OFFSET_ROOT_HASH,
                OFFSET_ROOT_FLAG,
            ),
            jbrahy_credential: read_credential_from_block(
                block,
                OFFSET_JBRAHY_SALT,
                OFFSET_JBRAHY_HASH,
                OFFSET_JBRAHY_FLAG,
            ),
        })
    }
}

fn write_credential_into_block(
    block: &mut [u8; CREDENTIAL_BLOCK_SIZE_IN_BYTES],
    credential: &Credential,
    salt_offset: usize,
    hash_offset: usize,
    flag_offset: usize,
) {
    block[salt_offset..salt_offset + SALT_LENGTH_IN_BYTES].copy_from_slice(&credential.salt);
    block[hash_offset..hash_offset + PASSWORD_HASH_LENGTH_IN_BYTES]
        .copy_from_slice(&credential.password_hash);
    block[flag_offset] = u8::from(credential.must_change_password);
}

fn read_credential_from_block(
    block: &[u8; CREDENTIAL_BLOCK_SIZE_IN_BYTES],
    salt_offset: usize,
    hash_offset: usize,
    flag_offset: usize,
) -> Credential {
    let mut salt = [0u8; SALT_LENGTH_IN_BYTES];
    salt.copy_from_slice(&block[salt_offset..salt_offset + SALT_LENGTH_IN_BYTES]);
    let mut password_hash = [0u8; PASSWORD_HASH_LENGTH_IN_BYTES];
    password_hash.copy_from_slice(&block[hash_offset..hash_offset + PASSWORD_HASH_LENGTH_IN_BYTES]);
    Credential {
        salt,
        password_hash,
        must_change_password: block[flag_offset] != 0,
    }
}

fn read_u32(block: &[u8; CREDENTIAL_BLOCK_SIZE_IN_BYTES], offset: usize) -> u32 {
    u32::from_le_bytes([
        block[offset],
        block[offset + 1],
        block[offset + 2],
        block[offset + 3],
    ])
}

fn sha256_of(bytes: &[u8]) -> [u8; PASSWORD_HASH_LENGTH_IN_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut output = [0u8; PASSWORD_HASH_LENGTH_IN_BYTES];
    output.copy_from_slice(&digest);
    output
}

/// Computes `SHA-256(salt || password)`.
fn hash_password_with_salt(
    salt: &[u8; SALT_LENGTH_IN_BYTES],
    password: &[u8],
) -> [u8; PASSWORD_HASH_LENGTH_IN_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password);
    let digest = hasher.finalize();
    let mut output = [0u8; PASSWORD_HASH_LENGTH_IN_BYTES];
    output.copy_from_slice(&digest);
    output
}

/// Compares two equal-length byte slices without early exit, so the time taken
/// does not depend on how many leading bytes match.
fn constant_time_bytes_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference_accumulator: u8 = 0;
    for index in 0..left.len() {
        difference_accumulator |= left[index] ^ right[index];
    }
    difference_accumulator == 0
}

#[cfg(test)]
mod tests {
    use super::{
        constant_time_bytes_equal, Credential, CredentialStore, UserIdentity,
        INITIAL_DEFAULT_PASSWORD, SALT_LENGTH_IN_BYTES,
    };

    fn fixed_salt(seed: u8) -> [u8; SALT_LENGTH_IN_BYTES] {
        [seed; SALT_LENGTH_IN_BYTES]
    }

    #[test]
    fn test_default_password_verifies_for_both_users() {
        let store = CredentialStore::with_default_passwords(fixed_salt(1), fixed_salt(2));
        assert_eq!(
            store.verify_login(b"root", INITIAL_DEFAULT_PASSWORD),
            Some(UserIdentity::Root)
        );
        assert_eq!(
            store.verify_login(b"jbrahy", INITIAL_DEFAULT_PASSWORD),
            Some(UserIdentity::Jbrahy)
        );
    }

    #[test]
    fn test_wrong_password_is_rejected() {
        let store = CredentialStore::with_default_passwords(fixed_salt(1), fixed_salt(2));
        assert_eq!(store.verify_login(b"root", b"wrongpass"), None);
        assert_eq!(store.verify_login(b"jbrahy", b"brainxo"), None);
    }

    #[test]
    fn test_unknown_user_is_rejected() {
        let store = CredentialStore::with_default_passwords(fixed_salt(1), fixed_salt(2));
        assert_eq!(store.verify_login(b"admin", INITIAL_DEFAULT_PASSWORD), None);
        assert_eq!(store.verify_login(b"", INITIAL_DEFAULT_PASSWORD), None);
    }

    #[test]
    fn test_both_users_must_change_password_initially() {
        let store = CredentialStore::with_default_passwords(fixed_salt(1), fixed_salt(2));
        assert!(store
            .credential_for(UserIdentity::Root)
            .must_change_password());
        assert!(store
            .credential_for(UserIdentity::Jbrahy)
            .must_change_password());
    }

    #[test]
    fn test_change_password_updates_hash_and_clears_flag() {
        let mut store = CredentialStore::with_default_passwords(fixed_salt(1), fixed_salt(2));
        store
            .credential_for_mut(UserIdentity::Root)
            .change_password(fixed_salt(9), b"newsecret");
        let root = store.credential_for(UserIdentity::Root);
        assert!(!root.must_change_password());
        assert!(root.verify_password(b"newsecret"));
        assert!(!root.verify_password(INITIAL_DEFAULT_PASSWORD));
    }

    #[test]
    fn test_same_password_different_salts_yields_different_hashes() {
        let credential_a = Credential::new_requiring_change(fixed_salt(1), b"brainxos");
        let credential_b = Credential::new_requiring_change(fixed_salt(2), b"brainxos");
        // Both verify their own password...
        assert!(credential_a.verify_password(b"brainxos"));
        assert!(credential_b.verify_password(b"brainxos"));
        // ...but the stored hashes differ because the salts differ.
        assert!(!constant_time_bytes_equal(
            &credential_a.verify_hash_for_test(),
            &credential_b.verify_hash_for_test()
        ));
    }

    #[test]
    fn test_constant_time_equal_matches_semantics() {
        assert!(constant_time_bytes_equal(b"abcd", b"abcd"));
        assert!(!constant_time_bytes_equal(b"abcd", b"abce"));
        assert!(!constant_time_bytes_equal(b"abc", b"abcd"));
    }

    #[test]
    fn test_serialize_round_trips_through_block() {
        let mut store = CredentialStore::with_default_passwords(fixed_salt(3), fixed_salt(4));
        store
            .credential_for_mut(UserIdentity::Jbrahy)
            .change_password(fixed_salt(7), b"changed");
        let block = store.serialize_to_block();
        let restored = CredentialStore::deserialize_from_block(&block).expect("valid block");
        // root unchanged: default password + must-change preserved.
        assert_eq!(
            restored.verify_login(b"root", INITIAL_DEFAULT_PASSWORD),
            Some(UserIdentity::Root)
        );
        assert!(restored
            .credential_for(UserIdentity::Root)
            .must_change_password());
        // jbrahy: changed password verifies, flag cleared, persisted.
        assert_eq!(
            restored.verify_login(b"jbrahy", b"changed"),
            Some(UserIdentity::Jbrahy)
        );
        assert!(!restored
            .credential_for(UserIdentity::Jbrahy)
            .must_change_password());
    }

    #[test]
    fn test_deserialize_rejects_corrupt_block() {
        let store = CredentialStore::with_default_passwords(fixed_salt(1), fixed_salt(2));
        let mut block = store.serialize_to_block();
        // Flip a payload byte; the checksum must now fail.
        block[10] ^= 0xFF;
        assert!(CredentialStore::deserialize_from_block(&block).is_none());
    }

    #[test]
    fn test_deserialize_rejects_blank_block() {
        let blank = [0u8; super::CREDENTIAL_BLOCK_SIZE_IN_BYTES];
        assert!(CredentialStore::deserialize_from_block(&blank).is_none());
    }

    #[test]
    fn test_login_name_round_trips() {
        assert_eq!(
            UserIdentity::from_login_name(b"root"),
            Some(UserIdentity::Root)
        );
        assert_eq!(UserIdentity::Root.login_name(), b"root");
        assert_eq!(UserIdentity::Jbrahy.login_name(), b"jbrahy");
    }
}
