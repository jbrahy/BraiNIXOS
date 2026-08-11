> # ⛔ SUPERSEDED — do not use as guidance
>
> **Superseded by [`architecture/BSP-v2-serving-protocol.md`](architecture/BSP-v2-serving-protocol.md)
> on 2026-08-02**, specifically its **admin session type**.
>
> The owner decision of 2026-08-02 (`ROADMAP.md` decision #17) chose a fixed, enumerated verb set over a
> shell, explicitly and on the record: administration is a second session *type* on the single
> authenticated, capability-gated transport, gated by `CapAdmin`, exposing exactly six verbs —
> enroll-key, revoke-key, load-weights, read-audit-log, restart-server, reboot. A general-purpose remote
> shell is a **non-goal** in [`NORTH_STAR.md`](NORTH_STAR.md), because a shell that can do anything is
> ambient authority under another name. The serial console is the break-glass path.
>
> **This design is not being built.** It is not a deferred item and not an unscheduled one; the question
> it answers was answered differently. Capability numbering and the verb set are normative in
> [`architecture/CAPABILITY_MODEL.md`](architecture/CAPABILITY_MODEL.md).
>
> Note also that the SSH server this spec assumes is **scheduled for deletion** at P2-T6.
>
> Retained unedited as a historical record of the design that was considered. See
> [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md).

---

# REMOTE_MANAGEMENT_SHELL_SPEC.md -- BraiNIX *(unscheduled)*

## Purpose

This document specifies the required functionality for remote operator access to a running BraiNIX system via a shell metaphor. The goal is operational management (inspection, configuration, lifecycle control of servers and capabilities) from a remote workstation, without compromising the structural security properties defined in `docs/security/SECURITY_INVARIANTS.md`.

POSIX compatibility is not a goal. POSIX-shaped ergonomics may be borrowed where they cost nothing in security; they are abandoned wherever they conflict with the capability model, the IPC model, or the unsafe-by-default policy.

## Non-Goals

- POSIX shell semantics, syntax, or scripting compatibility
- Multi-user identity model (no `/etc/passwd`, no UIDs, no PAM)
- Filesystem-backed configuration (no `~/.shrc`, no `/etc` files)
- Persistent shell state across reboots in version 1
- Job control in the POSIX sense (no `&`, no `fg`/`bg`, no process groups)
- Arbitrary scripting languages (no `eval`, no expression evaluator beyond bounded literals)
- General-purpose remote code execution (the operator composes capability invocations; they do not upload and run arbitrary code)

## Threat Model Additions

The remote management shell expands the system's attack surface. The following threats are added to those in `docs/security/THREAT_MODEL.md` and must be addressed structurally:

1. **Network adversary with full link control.** Can intercept, modify, replay, or drop any byte on the wire. Mitigated by mandatory authenticated encryption (Section 4) with no fallback or downgrade path.
2. **Stolen operator credential.** A compromised operator key grants access to the capabilities that operator's session is configured to receive. Mitigated by per-operator capability provisioning (Section 5) and short session lifetimes (Section 6).
3. **Malicious or buggy shell client.** The remote client is outside the TCB. The server must validate every byte received and must never trust client-supplied identifiers, capability references, or framing claims. Mitigated by structural parsing on the server side (Section 7) and badged endpoint identification.
4. **Replay of captured session traffic.** Mitigated by transport-layer nonces and forward secrecy (Section 4).
5. **Side-channel observation of capability use.** Out of scope for version 1; tracked in `docs/security/THREAT_MODEL.md` future work.

## Architectural Principles

The remote management shell preserves all principles in `PROJECT_RULES.md`. The following principles are specific to this subsystem:

- **The shell is a userspace server.** No shell logic runs in the kernel. The kernel exposes no shell-related syscalls.
- **The shell server holds no ambient authority.** It receives a bounded, named capability set at spawn time and may only act within those capabilities. It cannot escalate.
- **Each connected operator session is its own isolated process.** A session compromise does not grant access to other sessions, to the shell server, or to capabilities not explicitly granted to that session.
- **All operator authentication is by capability possession backed by cryptographic key.** No passwords. No challenge-response over secret-shared knowledge. The operator proves possession of a private key whose public counterpart is enrolled in the system.
- **The transport is mandatory-encrypted with no negotiation.** A single ciphersuite is supported. There is no version negotiation, no algorithm negotiation, no fallback. Mismatched client and server fail closed.
- **Every shell-server action is logged.** The shell server holds a `log_endpoint_capability` and emits a structured log entry for every command parsed, every capability invocation, every session lifecycle event, every authentication attempt.
- **No code is uploaded.** The operator cannot ship a binary to the system through the shell. Deploying new programs is a separate, signed, attested workflow defined in `docs/operations/RELEASE_AND_SIGNING_POLICY.md`.

## 1. System Decomposition

Remote management is implemented by the following userspace servers, each a separate process with bounded capabilities:

| Server | Responsibility |
|--------|----------------|
| `network_listener_server` | Accepts incoming TCP connections on the management port; performs no parsing of session content |
| `transport_security_server` | Terminates the encrypted transport; produces an authenticated bidirectional byte stream per session |
| `operator_authentication_server` | Verifies operator key signatures against the enrolled public key registry; issues session capabilities on success |
| `session_manager_server` | Spawns, supervises, and tears down per-operator session processes; holds the master capability set from which session caps are derived |
| `command_interpreter_server` | One instance per connected operator; parses commands, invokes capabilities, formats responses |
| `capability_registry_server` | Read-only lookup of named capabilities the operator session is permitted to reference |
| `log_server` | Receives structured log entries from all of the above (defined in `LOG_SERVER_SPEC.md`) |

No server in this list holds capabilities beyond those required for its single responsibility. The `command_interpreter_server` instance for a given operator holds only the subset of system capabilities that operator's session policy authorizes.

## 2. Connection Lifecycle

```
operator_workstation
        |
        |  TCP connect to management port
        v
network_listener_server  -- accepts socket, hands raw byte stream cap to -->
        |
        v
transport_security_server  -- performs handshake, on success hands plaintext byte stream cap to -->
        |
        v
operator_authentication_server  -- verifies operator signature, on success requests session from -->
        |
        v
session_manager_server  -- spawns -->
        |
        v
command_interpreter_server (per-operator instance)
        |
        |  bidirectional command/response over the authenticated stream
        v
operator_workstation
```

Each arrow represents a capability transfer. No server in the chain retains a capability to a downstream stage after handing off; the handoff transfers ownership.

## 3. Management Port

A single TCP port, fixed at compile time, is the only network entry point for remote management. The port is owned by `network_listener_server`, which holds a single bound-listen capability from the network stack. No other server may bind this port (capabilities are unique).

The management port is exposed only on network interfaces explicitly designated for management traffic in `device_manager` configuration. A system with no management interface enrolled has no remote management; the shell is unreachable by design.

## 4. Transport Security

### Mandatory ciphersuite

A single ciphersuite is supported. Version 1 selection:

- Key exchange: X25519 ECDH
- Authentication: Ed25519 signatures (operator and server identity)
- Bulk encryption: ChaCha20-Poly1305 AEAD
- Handshake transcript hashing: BLAKE3
- Forward secrecy: ephemeral key per session, discarded at session end

There is no algorithm negotiation. Both endpoints implement exactly this suite. A future ciphersuite migration is a coordinated client and server release, not a runtime negotiation.

### Handshake

The handshake is custom, minimal, and explicitly specified in `docs/security/REMOTE_TRANSPORT_HANDSHAKE.md` (to be authored). It is not TLS. TLS is rejected for this subsystem because:

- The TLS specification surface is incompatible with the minimum-auditable-code principle
- TLS implementations historically carry a heavy CVE burden in features this subsystem does not need (session resumption, 0-RTT, alert subprotocols, certificate chain validation, downgrade-prone negotiation)
- The use case is operator-to-server with both ends pre-enrolled, not arbitrary client to arbitrary server with a CA-rooted trust graph

The handshake produces:

- A symmetric bidirectional encrypted stream
- A verified operator public key identity
- A unique session nonce committed to in the transcript

### Replay and forward secrecy

Every session uses a fresh ephemeral keypair. Capture-and-replay of a complete session is detectable because the server-side ephemeral key is also fresh; the captured client messages will not validate against a new server ephemeral. Capture-and-decrypt-later is prevented by ephemeral key destruction at session end.

### Failure mode

Any handshake failure (bad signature, malformed message, version mismatch, unrecognized operator key) results in immediate connection termination, a log entry to `log_server`, and no diagnostic information returned to the client beyond connection close. Detailed failure reasons are available only in the system log. There is no "verbose error" mode and no remote way to request one.

## 5. Operator Identity and Enrollment

### Identity model

An operator is a public key. There is no username, no display name, no email, no group membership, no role hierarchy. The public key is the identity.

A human-readable label may be associated with an enrolled key for log readability. The label is metadata; it carries no authority and is not transmitted during authentication.

### Enrollment

Operator public keys are enrolled at system build time or via an out-of-band attested update workflow. Enrollment is not performed over the management shell itself, by structural rule: a shell that can enroll new operators is a shell that, if compromised, can grant attacker persistence. Enrollment is therefore handled by the same signed-image workflow that delivers the kernel and userspace binaries, defined in `docs/operations/RELEASE_AND_SIGNING_POLICY.md`.

An enrolled operator record contains:

- Public key (Ed25519, 32 bytes)
- Human-readable label (UTF-8, bounded length, metadata only)
- Session policy reference (which capability set this operator's sessions receive)
- Enrollment timestamp and enrolling-image signature

### Revocation

Revocation is by removal from the enrolled set in a subsequent signed image. There is no online revocation list, no CRL fetch, no OCSP equivalent. The system's enrolled operator set is whatever the currently running, attested image declares. Revoking an operator requires shipping a new image; this is intentional, to keep the trust graph entirely under the signing-and-attestation discipline.

## 6. Session Policy and Lifetime

### Session policy

Each operator's enrollment record references a named session policy. The policy declares which capabilities a session for that operator receives at spawn. Examples of policy-grantable capabilities:

- `process_listing_capability` (read-only enumeration of running processes)
- `process_termination_capability` (right to send shutdown to a running process)
- `log_reading_capability` (read access to the kernel and server log streams)
- `memory_inspection_capability` (read-only inspection of memory_server accounting)
- `capability_graph_inspection_capability` (read-only view of the system's CSpace graph)
- `device_manager_query_capability` (read-only enumeration of devices and drivers)
- `network_configuration_capability` (write access to network stack configuration)

A session never receives capabilities not declared in its policy. A read-only operator cannot, by structural rule, perform write operations, regardless of command syntax submitted.

Policies are defined at build time in a human-readable manifest, compiled into the system image, and attested by the same signing chain as the binaries.

### Session lifetime

A session has a maximum lifetime, fixed by policy, after which the `session_manager_server` tears it down regardless of operator activity. The default maximum is short (suggested: one hour) and may be reduced per policy but not extended at runtime.

A session also terminates on:

- Operator-initiated `disconnect` command
- Transport read/write error
- Idle timeout (suggested default: ten minutes; per-policy)
- `session_manager_server` administrative termination
- System shutdown

On termination, the per-session `command_interpreter_server` process exits; all capabilities held by that process are revoked by the kernel's normal process-exit cleanup. There is no surviving session state.

## 7. Command Interpreter

### Grammar

The command interpreter accepts one of two input modes. Both are server-side parsed; the client is not trusted to pre-parse.

**Line mode (default for interactive operator use):**

```
command_line     := invocation ( ';' invocation )*
invocation       := command_name ( argument )*
argument         := named_argument | positional_value
named_argument   := identifier '=' value
value            := string_literal | integer_literal | size_literal | capability_reference
capability_reference := '@' identifier ( '.' identifier )*
identifier       := letter ( letter | digit | '_' )*
string_literal   := '"' utf8_bytes_no_control_chars '"'
integer_literal  := digit+
size_literal     := digit+ ( "KiB" | "MiB" | "GiB" )
```

There is no shell expansion, no globbing, no variable substitution, no command substitution, no arithmetic, no backticks, no `eval`. The grammar is fixed; the parser is hand-written, total (no `panic!` on any byte sequence), and individually fuzz-tested.

**Structured mode (for tooling and automation):**

A length-prefixed binary encoding of the same command space. Defined in `docs/operations/REMOTE_SHELL_WIRE_FORMAT.md` (to be authored). Used by automation clients that should not depend on a text grammar.

The two modes are distinguished by the first byte of the post-handshake stream. There is no in-session mode switching.

### Command set, version 1

Commands are grouped by required capability. An operator session may invoke only commands whose required capabilities are present in the session.

**Always available (no special capability beyond session establishment):**

- `help` -- list invokable commands for this session
- `describe command_name=name` -- show usage for one command
- `list_capabilities` -- enumerate the capabilities held by this session
- `describe_capability reference=@name` -- show type, rights, derivation parent
- `whoami` -- print operator label and session identifier
- `disconnect` -- terminate this session

**Requiring `process_listing_capability`:**

- `list_processes` -- enumerate running processes with identifier, program name, state
- `describe_process identifier=N` -- detail for one process
- `list_servers` -- enumerate well-known servers and their endpoints

**Requiring `log_reading_capability`:**

- `read_log severity_minimum=info count=N` -- emit recent log entries
- `follow_log severity_minimum=info` -- stream log entries until interrupted

**Requiring `memory_inspection_capability`:**

- `report_memory_usage` -- per-process memory accounting
- `report_capability_counts` -- per-process CSpace occupancy

**Requiring `process_termination_capability`:**

- `terminate_process identifier=N reason="text"` -- request shutdown of a process

**Requiring `device_manager_query_capability`:**

- `list_devices` -- enumerate enrolled devices
- `describe_device identifier=name` -- detail for one device including driver server

**Requiring `network_configuration_capability`:**

- `list_network_interfaces` -- enumerate NICs and their assignments
- `set_network_interface_address identifier=name address=ipv4_or_ipv6 prefix_length=N`

This list is the version 1 floor. The set is intentionally small. New commands are added by:

1. Adding the command to the grammar and parser
2. Defining its required capability
3. Implementing the action against existing server endpoints
4. Adding the command to the relevant policy declarations
5. Shipping the change in a new signed image

There is no plugin model. There is no runtime command registration.

### Capability references

The `@name` syntax refers to a capability the session holds, looked up by name in the session's local capability registry. The registry is populated at session spawn from the policy and is read-only during the session. The operator cannot mint, derive, or transfer capabilities through the shell in version 1; capability manipulation is a future extension governed by its own policy capability.

### Output

Command output is structured. In line mode, the server formats structured output as human-readable text. In structured mode, the server emits the binary representation directly. Output is bounded per command; commands that would emit unbounded output (`follow_log`) stream incrementally and are terminable by the client sending a single defined control byte.

### Parser robustness requirements

The parser must:

- Be total: every byte sequence produces either a valid parsed command or a structured parse error, never a panic, never an infinite loop, never unbounded memory growth
- Bound input length: the maximum command line is fixed (suggested: 4 KiB); longer input is rejected before parsing
- Bound argument count: maximum arguments per command is fixed (suggested: 16)
- Reject control characters in string literals
- Reject non-UTF-8 byte sequences in string literals
- Be covered by continuous fuzzing in CI; any panic, hang, or memory growth from fuzzing is a release blocker

## 8. Logging Requirements

The `command_interpreter_server` emits a log entry, via `log_server`, for each of:

- Session establishment (operator label, session identifier, source address, policy name)
- Session termination (session identifier, reason)
- Each parsed command (session identifier, command name, argument summary with sensitive values redacted)
- Each capability invocation (session identifier, capability reference, target server, outcome)
- Each parse error (session identifier, error category; raw input is not logged to avoid log injection)
- Each authorization denial (session identifier, attempted command, missing capability)

Log entries are structured. The log format is defined in `LOG_SERVER_SPEC.md`. Logs are the audit record; their integrity is governed by `docs/operations/AUDIT_LOG_INTEGRITY_POLICY.md` (to be authored).

## 9. Client Software

A reference client implementation is provided as part of the BraiNIX source tree, written in the same Rust workspace, sharing the wire-format and grammar definitions with the server. The client:

- Implements the mandatory ciphersuite and handshake
- Provides line editing, history, and tab completion entirely client-side
- Holds the operator private key in memory only for the duration of the session, derived from a key file the operator supplies at invocation
- Never persists session content to disk
- Is the only supported client; third-party clients may be written against the published wire format but are not part of the TCB and are not supported

The client is not part of the running BraiNIX system. It runs on the operator's workstation under whatever operating system the operator chooses. The security of the operator's workstation is out of scope for this document; operators are advised to treat the workstation as part of their personal trust boundary.

## 10. What This Specification Forbids

To make the security posture explicit, the following are prohibited and any pull request introducing them is rejected:

- Any unauthenticated network entry point to management functionality
- Any password-based authentication path
- Any algorithm negotiation in the transport handshake
- Any remote operator enrollment path (enrollment is build-and-sign only)
- Any command that uploads, writes, or executes operator-supplied code
- Any command that reads or writes arbitrary memory addresses
- Any command that grants the session a capability not in its policy
- Any shell expansion, substitution, or scripting feature beyond the literal grammar
- Any persistent shell state across sessions or reboots in version 1
- Any client-trusted parsing or authorization (the server validates everything)
- Any TLS implementation in this subsystem
- Any logging of operator private keys, session keys, or raw parse-error input

## 11. Open Items for Future Specification

The following are deferred to subsequent documents and not part of version 1:

- `REMOTE_TRANSPORT_HANDSHAKE.md` -- detailed handshake message formats and state machine
- `REMOTE_SHELL_WIRE_FORMAT.md` -- structured-mode binary encoding
- `AUDIT_LOG_INTEGRITY_POLICY.md` -- log signing, rotation, off-system shipment
- Capability derivation through the shell (a future policy capability)
- Multi-operator coordination (concurrent sessions, soft locks on mutating commands)
- Out-of-band session attestation (operator-side verification of the running image)

## Document Status

Draft, version 1. Awaiting review against `SECURITY_INVARIANTS.md` and `THREAT_MODEL.md` for invariant numbering once those documents are finalized.
