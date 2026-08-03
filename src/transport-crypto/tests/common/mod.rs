//! Fixtures shared by the integration suites.
//!
//! Nothing here asserts; it only builds the two ends of a BSP v2 session so
//! each suite can attack one property at a time.

#![allow(dead_code)]

use brainix_bsp::CredentialRole;
use brainix_transport_crypto::{
    ClientHandshake, Credential, CredentialTable, EstablishedSession, ServerHandshake,
    TransportCryptoError,
};

/// The 32 bytes an operator would have handed `enroll-key`.
pub const ENROLLED_MATERIAL: [u8; 32] = [
    0x9e, 0x1c, 0x44, 0xb7, 0x03, 0xd8, 0x2a, 0x6f, 0x51, 0xe0, 0x77, 0x13, 0xbc, 0x95, 0x38, 0xaa,
    0x62, 0x0d, 0xf4, 0x81, 0x2c, 0x57, 0x9b, 0x30, 0xe6, 0x18, 0x73, 0xcf, 0x45, 0xa2, 0x6b, 0xd9,
];

/// A different 32 bytes — a peer that does **not** possess the PSK.
pub const IMPOSTOR_MATERIAL: [u8; 32] = [0x11u8; 32];

/// A client nonce with no structure worth reading into it.
pub const CLIENT_NONCE: [u8; 32] = [0x33u8; 32];

/// A server nonce, likewise.
pub const SERVER_NONCE: [u8; 32] = [0x77u8; 32];

/// Enrolls a credential from `material` without disturbing the caller's copy.
pub fn enroll(material: &[u8; 32], role: CredentialRole, flags: u8) -> Credential {
    let mut copy = *material;
    Credential::enroll(&mut copy, role, flags)
}

/// A credential table whose empty slots hold distinct per-boot filler.
pub fn empty_table() -> CredentialTable {
    let mut filler = [[0u8; 32]; brainix_bsp::MAX_ENROLLED_KEYS];
    for (index, slot) in filler.iter_mut().enumerate() {
        slot.fill(index as u8 ^ 0x5a);
    }
    CredentialTable::new(&mut filler)
}

/// A table holding exactly one credential enrolled from [`ENROLLED_MATERIAL`].
pub fn table_with_one_client() -> CredentialTable {
    let mut table = empty_table();
    let credential = enroll(&ENROLLED_MATERIAL, CredentialRole::Client, 0);
    table.insert(credential).expect("a fresh table has room");
    table
}

/// Both ends of a completed handshake.
pub struct Established {
    pub client: EstablishedSession,
    pub server: EstablishedSession,
    pub table: CredentialTable,
    pub credential: Credential,
}

/// Runs the whole §5.5 exchange and returns both sessions.
pub fn handshake() -> Established {
    handshake_with(&ENROLLED_MATERIAL, &CLIENT_NONCE, &SERVER_NONCE).expect("an honest handshake")
}

/// Runs the exchange with a client holding `client_material`, which may differ
/// from what the server has enrolled.
pub fn handshake_with(
    client_material: &[u8; 32],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> Result<Established, TransportCryptoError> {
    let mut table = table_with_one_client();
    let mut credential = enroll(client_material, CredentialRole::Client, 0);
    let (mut client, hello) = ClientHandshake::start(&credential, client_nonce);
    let mut server = ServerHandshake::new();
    let matched = server.identify(&hello, &table)?;
    let server_hello = server.derive(matched, server_nonce)?;
    let (auth, client_session) = client.accept_server_hello(&server_hello, &mut credential)?;
    let server_session = server.accept_client_auth(&auth, &mut table)?;
    Ok(Established {
        client: client_session,
        server: server_session,
        table,
        credential,
    })
}
