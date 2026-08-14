#![no_std]
#![deny(unsafe_code)]

//! The DART translation window, and the trait through which a driver holds one.
//!
//! `INV-DEV-006`: **"The IOMMU trait exposes no operation by which a driver can
//! enlarge, relocate, or add to its own translation window. Window changes are
//! made by the capability-bounded authority that granted the window, never by
//! its holder."** Its stated evidence is a Kani proof that no trait method
//! widens a window, and `src/dart-verify/` is that proof.
//!
//! # Why this is a type and not a check
//!
//! A driver that could ask for a wider window and be refused would be a driver
//! whose confinement depends on the refusal being correct on every path. The
//! shape here removes the question: [`DmaWindow`]'s only public transformations
//! *narrow* — [`DmaWindow::narrow`], [`DmaWindow::drop_write`],
//! [`DmaWindow::revoke`] — and none of them takes an authority argument,
//! because none of them can grant anything. There is no widening method to
//! refuse a call to.
//!
//! Granting is [`IommuAuthority`], which is a different trait held by a
//! different principal. That split is `INV-DEV-006`'s whole content: the holder
//! narrows, the granter grants.
//!
//! # Why this matters before there is a GPU
//!
//! `INV-DEV-006` is the structural control behind `INV-GPU`, and the GPU is the
//! *last* consumer to arrive. NVMe, PCIe and Ethernet are DMA-capable and land
//! first (AS-4). It is also precondition 2 of five for the **conditionally
//! signed TCB-AS/GPU exception**, which must be green *before Apple's GPU
//! firmware is ever loaded* — and, being a claim about an API surface rather
//! than about hardware, it can be discharged years before that firmware exists.
//!
//! # What AS-3 still owes
//!
//! Everything that touches a DART: per-instance discovery from the ADT, the PTE
//! formats (which differ across SoC generations), the register programming, and
//! the honest representation of an iBoot-locked instance. This crate is the
//! *shape* of the authority, which is the half that can be proved on a host.
//! A window here maps nothing; it says what a holder may do with what it was
//! given.

/// A translation window, in base pages.
///
/// Counted in pages rather than bytes for the same reason the reserved regions
/// are: the base page is 4 KiB on the frozen x86-64 reference and 16 KiB on
/// Apple Silicon, and a window measured in bytes is a page-size assumption
/// waiting to be wrong (`INV-MEM-009`).
///
/// The empty window is the default and denies everything (`INV-DEV-004`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaWindow {
    base_page: u64,
    pages: u64,
    writable: bool,
}

impl Default for DmaWindow {
    fn default() -> Self {
        Self::deny_all()
    }
}

impl DmaWindow {
    /// The window that permits nothing.
    ///
    /// `INV-DEV-004`: every discovered DART instance defaults to deny-all. This
    /// is what "default" means here — not a permissive window awaiting
    /// configuration, but an empty one, so an instance nobody programmed
    /// translates nothing.
    #[must_use]
    pub const fn deny_all() -> Self {
        Self {
            base_page: 0,
            pages: 0,
            writable: false,
        }
    }

    /// A window granted by the authority that owns the address space.
    ///
    /// Deliberately **not** callable in a useful way by a holder: it is how
    /// [`IommuAuthority`] expresses a grant, and a driver that calls it has
    /// granted itself a window over an address space it does not own — which
    /// the capability model, not this type, is what prevents. The type's job is
    /// that *holding* a window confers no way to enlarge it.
    ///
    /// **A grant whose extent does not compute grants nothing.** If
    /// `base_page + pages` overflows, this returns [`Self::deny_all`] rather
    /// than a window, because such a window contains nothing — not even itself
    /// — and a holder of one could not narrow it, drop write on it, or reason
    /// about it at all. Kani found this: the monotonicity proofs failed on
    /// exactly these windows, and the honest fix is to make them
    /// unconstructible rather than to assume them away in the harness. A
    /// granter that computes an overflowing extent has a bug, and an empty
    /// window is the fail-closed answer to it.
    #[must_use]
    pub const fn granted(base_page: u64, pages: u64, writable: bool) -> Self {
        if base_page.checked_add(pages).is_none() {
            return Self::deny_all();
        }
        Self {
            base_page,
            pages,
            writable,
        }
    }

    /// First page of the window.
    #[must_use]
    pub const fn base_page(&self) -> u64 {
        self.base_page
    }

    /// Length of the window in pages.
    #[must_use]
    pub const fn pages(&self) -> u64 {
        self.pages
    }

    /// Whether the window permits writes.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.writable
    }

    /// Whether the window translates nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pages == 0
    }

    /// The first page past the window, or `None` if that does not compute.
    ///
    /// A window whose end overflows is not treated as very large: every
    /// containment question about it answers "no" (see [`Self::contains`]), so
    /// it can neither be narrowed into nor claim to contain anything.
    #[must_use]
    pub const fn end_page(&self) -> Option<u64> {
        self.base_page.checked_add(self.pages)
    }

    /// Whether every page of `other` is a page of `self`.
    ///
    /// The empty window is contained in everything — it names no page — and
    /// contains nothing but other empty windows.
    #[must_use]
    pub const fn contains(&self, other: &Self) -> bool {
        if other.is_empty() {
            return true;
        }
        if self.is_empty() {
            return false;
        }
        let (Some(self_end), Some(other_end)) = (self.end_page(), other.end_page()) else {
            return false;
        };
        self.base_page <= other.base_page && other_end <= self_end
    }

    /// Whether `other` confers no authority `self` does not already confer.
    ///
    /// Containment plus write authority: a sub-range that gained the write bit
    /// is a widening even though its pages are a subset, which is the case a
    /// range-only check would wave through.
    #[must_use]
    pub const fn permits_everything_in(&self, other: &Self) -> bool {
        if !self.contains(other) {
            return false;
        }
        if other.is_empty() {
            return true;
        }
        self.writable || !other.writable
    }

    /// Narrows to a sub-range of this window.
    ///
    /// The only way a holder changes its own window, and it can only shrink it.
    /// The resulting window never gains the write bit: it inherits this
    /// window's, so a read-only grant cannot be narrowed into a writable one.
    ///
    /// # Errors
    ///
    /// [`WindowError::NotContained`] if the requested range is not wholly
    /// inside this window — including any range whose end does not compute.
    /// Denies rather than clamping: a clamped request silently hands back a
    /// different window than the caller asked for, and a caller that wanted
    /// pages it does not own should learn that it does not own them.
    pub const fn narrow(&self, base_page: u64, pages: u64) -> Result<Self, WindowError> {
        let requested = Self {
            base_page,
            pages,
            writable: self.writable,
        };
        if !self.contains(&requested) {
            return Err(WindowError::NotContained);
        }
        Ok(requested)
    }

    /// Drops write authority, keeping the range.
    ///
    /// Monotone in the only direction this type allows.
    #[must_use]
    pub const fn drop_write(&self) -> Self {
        Self {
            base_page: self.base_page,
            pages: self.pages,
            writable: false,
        }
    }

    /// Gives up the window entirely.
    #[must_use]
    pub const fn revoke(&self) -> Self {
        Self::deny_all()
    }
}

/// Why a window operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowError {
    /// The requested range is not wholly inside the current window.
    NotContained,
}

/// What a **holder** of a window may do: narrow it, drop write, give it up.
///
/// Deliberately without a `grant`, a `widen`, a `relocate`, or an `add`. This
/// trait is the API surface `INV-DEV-006` is a claim about, and the claim is
/// discharged by what is absent from it as much as by what the present methods
/// do. A future method here that returns a window not contained in the current
/// one breaks the proof in `src/dart-verify/`, which is the point of writing
/// the proof against the trait rather than against one implementation.
pub trait IommuWindowHolder {
    /// The window this holder currently has.
    fn window(&self) -> DmaWindow;

    /// Narrows the held window to a sub-range.
    ///
    /// # Errors
    ///
    /// [`WindowError::NotContained`] if the range is not inside the current
    /// window.
    fn narrow_window(&mut self, base_page: u64, pages: u64) -> Result<(), WindowError>;

    /// Drops write authority from the held window.
    fn drop_write_authority(&mut self);

    /// Gives up the window.
    fn revoke_window(&mut self);
}

/// What the **granting authority** may do — held by a different principal.
///
/// The split is `INV-DEV-006`'s content: "window changes are made by the
/// capability-bounded authority that granted the window, never by its holder."
/// A driver holds [`IommuWindowHolder`]; whoever owns the address space holds
/// this.
pub trait IommuAuthority {
    /// Grants a window to a device.
    fn grant(&mut self, device: u16, window: DmaWindow);

    /// Revokes a device's window, returning it to deny-all.
    fn revoke(&mut self, device: u16);
}

/// A holder that owns its window value: the reference implementation of the
/// holder half, and what the proofs drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldWindow {
    window: DmaWindow,
}

impl Default for HeldWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl HeldWindow {
    /// A holder with nothing granted to it.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            window: DmaWindow::deny_all(),
        }
    }

    /// A holder of an already-granted window.
    #[must_use]
    pub const fn holding(window: DmaWindow) -> Self {
        Self { window }
    }
}

impl IommuWindowHolder for HeldWindow {
    fn window(&self) -> DmaWindow {
        self.window
    }

    fn narrow_window(&mut self, base_page: u64, pages: u64) -> Result<(), WindowError> {
        self.window = self.window.narrow(base_page, pages)?;
        Ok(())
    }

    fn drop_write_authority(&mut self) {
        self.window = self.window.drop_write();
    }

    fn revoke_window(&mut self) {
        self.window = self.window.revoke();
    }
}
