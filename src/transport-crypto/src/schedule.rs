//! §5.4 — transcript hashes and the session key schedule.
//!
//! ```text
//! TH_1 = SHA256( ClientHello[0..64] || ServerHello[0..32] )    # ServerHello's nonce only
//! TH_2 = SHA256( ClientHello[0..64] || ServerHello[0..64] )    # full ServerHello
//!
//! PRK_session    = HKDF-Extract(salt = TH_1, ikm = CK_m)
//!
//! server_confirm = HKDF-Expand(PRK_session, LABEL_SRV_CONFIRM || role,          32)
//! client_confirm = HKDF-Expand(PRK_session, LABEL_CLI_CONFIRM || role || TH_2,  32)
//! K_c2s          = HKDF-Expand(PRK_session, LABEL_KEYS_C2S    || role,          64)
//! K_s2c          = HKDF-Expand(PRK_session, LABEL_KEYS_S2C    || role,          64)
//! session_id     = TH_2
//! ```
//!
//! `TH_1` covers only `ServerHello`'s nonce, and that is what makes the
//! schedule computable: `server_confirm` is a function of `PRK_session`, which
//! is a function of `TH_1`, so `TH_1` cannot depend on `server_confirm`. `TH_2`
//! then closes over it.
//!
//! # Why every input length here is a compile-time constant
//!
//! §5.6b: "Because every input length is a compile-time constant there is no
//! canonicalization ambiguity: two distinct transcripts cannot produce the same
//! hash input." That is enforced by the signatures below — every argument is a
//! fixed-size array, never a slice — so there is no call site at which a
//! variable-length value could reach a transcript hash.
//!
//! # `session_id` is internal
//!
//! §5.4: it is used for audit correlation and nothing else. It is **never on
//! the wire** and is never a routable name (`INV-SERVE-001`).

use brainix_bsp::{LEN_CLIENT_HELLO, LEN_CONFIRM, LEN_DIR_KEYS, LEN_NONCE};
use brainix_sha256::Sha256;

use crate::hkdf::{expand, extract};
use crate::labels::{
    info_client_confirm, info_label_role, LABEL_KEYS_C2S, LABEL_KEYS_S2C, LABEL_SRV_CONFIRM,
};
use crate::ratchet::ChainKey;
use crate::record::DirectionKeys;
use crate::secret::Secret;

/// Bytes in a transcript hash — SHA-256's output.
pub const LEN_TRANSCRIPT: usize = 32;

/// `TH_1 = SHA256(ClientHello || server_nonce)` (§5.4).
#[must_use]
pub fn transcript_one(
    client_hello: &[u8; LEN_CLIENT_HELLO],
    server_nonce: &[u8; LEN_NONCE],
) -> [u8; LEN_TRANSCRIPT] {
    let mut hasher = Sha256::new();
    hasher.update(client_hello);
    hasher.update(server_nonce);
    hasher.finalize()
}

/// `TH_2 = SHA256(ClientHello || server_nonce || server_confirm)` (§5.4).
///
/// The second half of the input is the full `ServerHello` image, in the field
/// order §5.1 fixes.
#[must_use]
pub fn transcript_two(
    client_hello: &[u8; LEN_CLIENT_HELLO],
    server_nonce: &[u8; LEN_NONCE],
    server_confirm: &[u8; LEN_CONFIRM],
) -> [u8; LEN_TRANSCRIPT] {
    let mut hasher = Sha256::new();
    hasher.update(client_hello);
    hasher.update(server_nonce);
    hasher.update(server_confirm);
    hasher.finalize()
}

/// Everything §5.4 derives from one transcript and one chain key.
///
/// The two confirmations are both eventually public — each is sent by the party
/// that computes it — but the *expected* value a verifier holds before the peer
/// sends it is a secret, so both are [`Secret`]s and both are compared through
/// [`Secret::ct_eq_bytes`].
pub struct SessionSecrets {
    server_confirm: Secret<LEN_CONFIRM>,
    client_confirm: Secret<LEN_CONFIRM>,
    client_to_server: Secret<LEN_DIR_KEYS>,
    server_to_client: Secret<LEN_DIR_KEYS>,
    session_id: [u8; LEN_TRANSCRIPT],
}

/// Which end of the connection a set of directional keys is being installed on.
///
/// The only thing it decides is which direction seals and which opens; both
/// ends derive the same two key sets from the same transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The server: seals with `K_s2c`, opens with `K_c2s`.
    Server,
    /// The client: seals with `K_c2s`, opens with `K_s2c`.
    Client,
}

impl SessionSecrets {
    /// Runs the whole of §5.4 over `CK_m` and the transcript.
    ///
    /// `PRK_session` is a local [`Secret`] and is destroyed when this function
    /// returns. `CK_m` is borrowed and is the caller's to destroy — it belongs
    /// to a [`ScratchChain`](crate::ratchet::ScratchChain), whose `Drop` does.
    #[must_use]
    pub fn derive(
        chain_key: &ChainKey,
        role: u8,
        client_hello: &[u8; LEN_CLIENT_HELLO],
        server_nonce: &[u8; LEN_NONCE],
    ) -> Self {
        let transcript_1 = transcript_one(client_hello, server_nonce);
        let session_prk = extract(&transcript_1, chain_key.expose());
        let server_confirm =
            expand::<LEN_CONFIRM>(&session_prk, &info_label_role(&LABEL_SRV_CONFIRM, role));
        let session_id = transcript_two(client_hello, server_nonce, server_confirm.expose());
        Self {
            client_confirm: expand::<LEN_CONFIRM>(
                &session_prk,
                &info_client_confirm(role, &session_id),
            ),
            client_to_server: expand::<LEN_DIR_KEYS>(
                &session_prk,
                &info_label_role(&LABEL_KEYS_C2S, role),
            ),
            server_to_client: expand::<LEN_DIR_KEYS>(
                &session_prk,
                &info_label_role(&LABEL_KEYS_S2C, role),
            ),
            server_confirm,
            session_id,
        }
    }

    /// The value this end puts in `ServerHello`, or expects to find there.
    #[must_use]
    pub const fn server_confirm(&self) -> &Secret<LEN_CONFIRM> {
        &self.server_confirm
    }

    /// The value this end puts in `ClientAuth`, or expects to find there.
    #[must_use]
    pub const fn client_confirm(&self) -> &Secret<LEN_CONFIRM> {
        &self.client_confirm
    }

    /// `session_id = TH_2` — audit correlation only, never on the wire.
    #[must_use]
    pub const fn session_id(&self) -> &[u8; LEN_TRANSCRIPT] {
        &self.session_id
    }

    /// Splits the two 64-byte directional outputs into the record layer's
    /// `(seal, open)` key pair for `side`.
    ///
    /// Consumes `self`, so the derived material has exactly one owner
    /// afterwards and the confirmations are zeroized as this value drops.
    #[must_use]
    pub fn into_direction_keys(self, side: Side) -> (DirectionKeys, DirectionKeys) {
        let client_to_server = self.client_to_server.clone();
        let server_to_client = self.server_to_client.clone();
        match side {
            Side::Server => (
                DirectionKeys::from_material(server_to_client),
                DirectionKeys::from_material(client_to_server),
            ),
            Side::Client => (
                DirectionKeys::from_material(client_to_server),
                DirectionKeys::from_material(server_to_client),
            ),
        }
    }

    /// Destroys every derived value — §9.4's teardown, and the abort path of a
    /// handshake that failed after derivation.
    pub fn zeroize(&mut self) {
        self.server_confirm.zeroize();
        self.client_confirm.zeroize();
        self.client_to_server.zeroize();
        self.server_to_client.zeroize();
        self.session_id.fill(0);
    }
}
