> # ⛔ SUPERSEDED — do not use as guidance
>
> **Superseded by [`security/SECURITY_INVARIANTS.md`](security/SECURITY_INVARIANTS.md) and
> [`NORTH_STAR.md`](NORTH_STAR.md) on 2026-08-02.**
>
> Written 2026-04-11 — the oldest security document in the tree. Its foundational principles survive
> (they were folded into the north-star's first principles), but it predates the named-invariant scheme
> entirely, and invariants are now stated in exactly one place: `NORTH_STAR.md`.
>
> Retained unedited as a historical record. See [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md).

---

## Foundational rules *(historical — superseded)*

1. **Security must be structural, not probabilistic.** No core security guarantee may depend on obscurity, address secrecy, or an attacker not knowing the design. Defense-in-depth mitigations are allowed, but the system must remain secure even when the architecture is fully known.

2. **The kernel must stay tiny.** Only code that absolutely must run in ring 0 belongs in the kernel. Everything else must live in isolated userspace services.

3. **No ambient authority anywhere.** Every access to memory, IPC, devices, interrupts, scheduling controls, or mapping rights must require an explicit typed capability.

4. **Compatibility never outranks security.** POSIX, legacy Unix semantics, convenience APIs, and “industry-standard expectations” must not be added if they weaken capability purity or trust boundaries.

5. **Every trust boundary must be written down.** The project must maintain an explicit TCB document and separate development-mode claims from production-mode claims.

## Design and architecture rules

6. **Development and production are different systems.** QEMU, Docker, swtpm, CI, and the host kernel are acceptable for development, but no production-strength security claim may assume they are trustworthy.

7. **x86-64 only means x86-64 only.** No 32-bit mode, no legacy compatibility burden, no extra platform scope until the 64-bit secure baseline is complete.

8. **No shared memory by default.** Control flow between processes must use kernel-mediated synchronous IPC. Any future high-performance memory sharing must be explicitly capability-governed, revocable, bounded, and documented.

9. **Every security property must have a named invariant.** If the team cannot state the invariant in one sentence, the feature is not ready to ship.

10. **No feature enters the kernel without a threat model.** Every new subsystem must name what it protects, what it trusts, what it exposes, and how it fails.

## Authority and capability rules

11. **Capabilities are the only authority mechanism.** There must be no hidden globals, special-case privilege bits, process identity shortcuts, or “root-like” escape hatches.

12. **Capabilities may never gain rights through movement.** Transfer, copy, delegation, and derivation must be monotonic. No operation may amplify authority.

13. **Revocation must be complete and final.** Once revocation completes, no child, alias, stale slot, cached lookup, or borrowed handle may still function.

14. **Capability slots must be sanitized on revoke and free.** No ghost references, stale metadata, or partially-cleared slots.

15. **Capabilities must be quota-controlled.** No process or security domain may consume unbounded cap slots, derivation depth, or kernel object references.

16. **Do not add temporal capabilities to the trusted core until the basic model is proven stable.** Keep the first secure core simple.

## Memory safety and isolation rules

17. **W^X is absolute.** No writable-executable mappings anywhere in the system.

18. **Kernel memory must never be directly user-accessible.** KPTI or equivalent isolation must ensure the kernel is not casually mapped into user space.

19. **Every object class must have separate allocation policy.** Kernel objects, user pages, IPC buffers, and device memory must not be casually mixed.

20. **No unbounded dynamic kernel heap.** Use fixed-size or tightly bounded allocators with explicit exhaustion behavior. Silent fallback is forbidden.

21. **All freed memory must be sanitized before reuse.** Pages, object slabs, IPC buffers, stacks, and audit-sensitive memory must be zeroed or otherwise safely reset before reallocation.

22. **Kernel stacks must be guarded.** Guard pages are mandatory, and critical fault paths should use separate known-good stacks.

23. **All pointer-bearing unsafe code must be isolated and reviewed as security-critical code.**

## Rust and implementation rules

24. **Rust is a tool, not the proof.** The system may never claim “secure because Rust.” Rust reduces categories of bugs, but invariants, unsafe boundaries, and architecture rules still carry the real security burden.

25. **Unsafe code must be budgeted.** Every `unsafe` block must explain its invariants, preconditions, aliasing assumptions, and failure modes.

26. **Unsafe must be centralized.** Raw page-table code, interrupt/CPU state manipulation, FFI boundaries, boot code, and hardware register access must live in small, isolated modules.

27. **No unchecked parsing in trusted code.** ELF loading, boot structures, IPC payload decoding, and device input parsing must be bounded and validated.

28. **Panics in privileged code must be treated as security events.** Kernel panic behavior must be deterministic, logged, and never continue in an undefined state.

## IPC and liveness rules

29. **IPC must be synchronous, typed, and bounded.** Sender and receiver synchronization rules must be explicit, and no IPC path may block forever.

30. **Timeouts are mandatory.** If a service does not respond, the caller must recover predictably.

31. **Reply paths must be non-forgeable.** Reply capabilities or reply objects must be single-purpose and never reusable as general authority.

32. **Cancellation must exist.** The kernel must define what happens when one side dies, times out, or is restarted during an IPC exchange.

33. **Deadlock-prone call patterns must be forbidden or mechanically checked.** Do not rely on developer discipline alone.

## Scheduler and availability rules

34. **Availability is part of security.** The design must treat denial of service, starvation, and dependency lockup as security problems, not mere performance problems.

35. **All resource use must be quota-enforced per security domain.** CPU, memory, IPC buffers, cap slots, audit storage, and kernel objects must all have limits.

36. **Priority inversion must be actively controlled.** If priority inheritance is used, it must be correct and bounded.

37. **One compromised service must not be able to exhaust the platform.** Pool exhaustion behavior must be explicit and fail closed.

38. **SMT isolation must be enforced where security domains differ.** No cross-domain sibling hyperthread scheduling in high-assurance mode.

## x86 hardware rules

39. **NX is mandatory.** No execute permission on data pages.

40. **SMEP is mandatory in production.** Kernel execution of user pages must be blocked.

41. **SMAP is mandatory in production.** Kernel access to user mappings must be controlled and deliberate.

42. **CET/IBT must be enabled where supported.** Unsupported features must be documented plainly, not hand-waved.

43. **Kernel text and read-only data must be write-protected after init.**

44. **IOMMU is required for production device isolation.** Device-process isolation is not enough if DMA can bypass memory boundaries.

45. **Microcode and mitigation baselines must be versioned.** The project must define the minimum CPU/microcode state required for production trust.

46. **Speculative-execution policy must be explicit.** If you mitigate Spectre-class issues, state exactly which classes are covered and which are not.

## Boot, attestation, and trust rules

47. **Measured boot claims must be production-only.** swtpm and virtual TPM flows are for development validation, not root-of-trust claims.

48. **Dev and prod keys must be completely separate.** No shared signing, attestation, or provisioning material.

49. **No unsigned privileged component may boot.** Bootloader, kernel, and critical early userspace must all be authenticated in production.

50. **Rollback must be treated as an attack.** Version counters, measurement policy, and update rules must prevent reverting to known-vulnerable code.

51. **Entropy policy must be based on cryptographic sufficiency, not blind trust in one source.** Do not tie the whole system’s security story to a single hardware RNG assumption.

## Userspace and service rules

52. **Every userspace service starts with the minimum capabilities needed and nothing more.**

53. **`init` must not remain an all-powerful runtime god process.** Bootstrap authority must be shed as early as possible.

54. **Spawning must be policy-controlled.** Process creation authority must be narrow, reviewable, and never implicit.

55. **Each device gets its own isolation boundary where practical.** Do not collapse unrelated hardware trust into a single giant driver process.

56. **Network stack layers must remain separated.** Link, IP, and transport responsibilities should stay isolated so compromise in one layer does not automatically own the whole stack.

57. **Audit consumers must not be able to rewrite history.** Audit access should be append-only or read-only according to role.

## Supply chain and build rules

58. **Builds must be reproducible and offline-capable.** Security cannot depend on live internet state during trusted builds.

59. **Every dependency must be pinned, reviewed, and justified.** Rust nightly must be pinned; crate intake must be controlled.

60. **Supply-chain checks are mandatory in CI.** Vendoring, `cargo vet`, `cargo deny`, and `cargo audit` must be enforced, not optional.

61. **Verification jobs must be isolated.** If verification tools require different pinned toolchains, isolate them cleanly instead of weakening reproducibility. *(Kani is the only such tool as of 2026-08-12; Prusti was removed — see `security/SECURITY_INVARIANTS.md` §16. Kani's installation is deliberately performed before checkout, because the repository's vendored-sources config otherwise breaks its installer.)*

62. **No “temporary” CI bypasses in the main branch.** Any exception mechanism becomes permanent attack surface.

## Verification and testing rules

63. **Every core subsystem must have a proof target or fuzz target.** Capability logic, IPC, syscall validation, loader paths, and memory transitions must be tested adversarially.

64. **Formal methods must have explicit scope.** Never imply that proving one subsystem proves the whole kernel.

65. **Security regressions must block merges.** If an invariant, proof, fuzz target, sanitizer, or build reproducibility check fails, the change does not land.

66. **Every bug fix must add a permanent test.** No one-off patches without a regression test.

67. **Security review is required for all new kernel features.** Not optional, not delegated to “later.”

## Process and governance rules

68. **The project must maintain a living threat model.** It must be updated before major design changes, not after incidents.

69. **Out-of-scope items must be written down explicitly.** Unclaimed protection is better than implied protection.

70. **Every security claim must map to code, docs, and tests.** No marketing-language guarantees.

71. **Complexity is treated as a vulnerability source.** If a feature meaningfully expands the TCB, semantic surface, or unsafe surface, it must clear a very high bar.

72. **When security and convenience conflict, security wins by default.**

73. **When simplicity and cleverness conflict, simplicity wins by default.**

74. **When uncertainty exists, the system fails closed.**

## The shortest version

If you want the entire project reduced to a one-page constitution, it is this:

* keep the kernel tiny
* allow no ambient authority
* make every privilege explicit
* make every boundary typed and revocable
* trust as little hardware and software as possible
* separate dev claims from prod claims
* keep unsafe code tiny and documented
* fail closed on ambiguity
* quota everything
* verify everything important
* never let compatibility weaken the model
