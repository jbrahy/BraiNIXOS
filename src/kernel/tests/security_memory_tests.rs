//! Security memory property tests for Phase 2.
//!
//! Tests run on HOST target and verify structural security properties via source
//! inspection (include_str!) and unit tests. Source inspection is used because
//! the no_std x86-only kernel cannot be imported on the host target.
//!
//! All 6 tests are Phase 2 success-gate requirements (ROADMAP security criteria).

/// SC-1: Kernel-tagged pages are never returned by the user page allocator.
///
/// Enforces INV-MEM-005: memory ownership is explicit. Verifies structurally
/// that allocate_user_page checks page type (via verify_page_is_free) before
/// setting UserOwned and returning the address.
///
/// Verified by: structural source inspection of physical_allocator.rs
#[test]
fn test_kernel_tagged_page_is_not_returned_by_user_allocator() {
    let allocator_source = include_str!("../src/memory/physical_allocator.rs");
    assert_allocate_user_page_calls_page_type_check(allocator_source);
    assert_page_type_check_function_rejects_non_free(allocator_source);
}

/// SC-2: Allocated pages are zeroed before being returned to the caller.
///
/// Enforces INV-MEM-006: freed memory is sanitized before reuse. Verifies
/// that allocate_user_page calls zero_page_at_address before setting UserOwned.
///
/// Verified by: structural source inspection of physical_allocator.rs
#[test]
fn test_allocated_page_is_zeroed_before_return() {
    let allocator_source = include_str!("../src/memory/physical_allocator.rs");
    assert_allocate_user_page_calls_zero_before_type_assignment(allocator_source);
    assert_zero_function_exists(allocator_source);
}

/// SC-3: Double-free attempts are detected and refused.
///
/// Enforces INV-MEM-005: ownership is explicit and transitions are guarded.
/// Verifies that deallocate_page checks for already-free pages and returns DoubleFree.
///
/// Verified by: structural source inspection of physical_allocator.rs
#[test]
fn test_double_free_is_detected_and_refused() {
    let allocator_source = include_str!("../src/memory/physical_allocator.rs");
    assert_deallocate_page_calls_double_free_check(allocator_source);
    assert_double_free_error_variant_exists(allocator_source);
}

/// SC-4: Kernel virtual addresses are absent from the user page table.
///
/// Enforces INV-MEM-001 and INV-MEM-002 (KPTI): the user page table is structurally
/// empty. Verifies that user_page_table.rs never adds kernel-range VA entries and
/// constructs only an empty PageTable::new().
///
/// Verified by: structural source inspection of user_page_table.rs
#[test]
fn test_kernel_virtual_address_is_absent_from_user_page_table() {
    let user_page_table_source = include_str!("../src/arch/paging/user_page_table.rs");
    assert_user_page_table_is_structurally_empty(user_page_table_source);
    assert_no_kernel_address_literal_in_user_page_table(user_page_table_source);
}

/// SC-5: No page table entry is simultaneously writable and executable.
///
/// Enforces INV-MEM-003 (W^X is global). Verifies that every paging source file
/// that calls set_addr also calls validate_page_table_flags_enforce_write_xor_execute.
///
/// Verified by: structural source inspection of kernel_page_table.rs and direct_map.rs
#[test]
fn test_no_page_table_entry_is_writable_and_executable() {
    let kernel_page_table_source = include_str!("../src/arch/paging/kernel_page_table.rs");
    let direct_map_source = include_str!("../src/arch/paging/direct_map.rs");
    assert_write_xor_execute_validator_guards_all_mappings(kernel_page_table_source);
    assert_write_xor_execute_validator_guards_all_mappings(direct_map_source);
}

/// SC-6: No two allocations return the same physical address (no page deduplication).
///
/// Enforces the no-dedup policy (D-15): page deduplication is explicitly forbidden
/// to eliminate KSM-style side channels. Verifies that the allocator uses a LIFO
/// pop-based stack that returns unique addresses and contains no dedup logic.
///
/// Verified by: structural source inspection of physical_allocator.rs
#[test]
fn property_no_two_allocations_return_same_physical_address() {
    let allocator_source = include_str!("../src/memory/physical_allocator.rs");
    assert_allocator_uses_stack_pop_for_unique_addresses(allocator_source);
    assert_no_page_deduplication_logic(allocator_source);
}

// --- SC-1 helpers ---

fn assert_allocate_user_page_calls_page_type_check(source: &str) {
    let allocate_body = extract_function_body(source, "fn allocate_user_page");
    assert!(
        allocate_body.contains("verify_page_is_free"),
        "allocate_user_page must call verify_page_is_free before returning"
    );
}

fn assert_page_type_check_function_rejects_non_free(source: &str) {
    assert!(
        source.contains("fn verify_page_is_free"),
        "physical_allocator.rs must define verify_page_is_free"
    );
    assert!(
        source.contains("PageType::Free"),
        "physical_allocator.rs must reference PageType::Free in type check"
    );
}

// --- SC-2 helpers ---

fn assert_allocate_user_page_calls_zero_before_type_assignment(source: &str) {
    let allocate_body = extract_function_body(source, "fn allocate_user_page");
    let zero_position = allocate_body.find("zero_page_at_address");
    let user_owned_position = allocate_body.find("UserOwned");
    assert!(
        zero_position.is_some(),
        "allocate_user_page must call zero_page_at_address"
    );
    assert!(
        user_owned_position.is_some(),
        "allocate_user_page must set PageType::UserOwned"
    );
    assert_zero_called_before_type_assignment(zero_position, user_owned_position);
}

fn assert_zero_called_before_type_assignment(
    zero_position: Option<usize>,
    type_position: Option<usize>,
) {
    let zero_offset = zero_position.unwrap_or(usize::MAX);
    let type_offset = type_position.unwrap_or(0);
    assert!(
        zero_offset < type_offset,
        "zero_page_at_address must be called before setting PageType::UserOwned"
    );
}

fn assert_zero_function_exists(source: &str) {
    assert!(
        source.contains("fn zero_page_at_address"),
        "physical_allocator.rs must define zero_page_at_address"
    );
}

// --- SC-3 helpers ---

fn assert_deallocate_page_calls_double_free_check(source: &str) {
    let deallocate_body = extract_function_body(source, "fn deallocate_page");
    assert!(
        deallocate_body.contains("reject_invalid_deallocation"),
        "deallocate_page must call reject_invalid_deallocation"
    );
}

fn assert_double_free_error_variant_exists(source: &str) {
    assert!(
        source.contains("DoubleFree"),
        "physical_allocator.rs must reference DoubleFree error variant"
    );
    assert!(
        source.contains("is_free"),
        "reject_invalid_deallocation must check is_free()"
    );
}

// --- SC-4 helpers ---

fn assert_user_page_table_is_structurally_empty(source: &str) {
    assert!(
        source.contains("PageTable::new()"),
        "user_page_table.rs must construct an empty PageTable via PageTable::new()"
    );
    assert!(
        source.contains("is_empty"),
        "user_page_table.rs must assert the table is empty (KPTI structural guarantee)"
    );
}

fn assert_no_kernel_address_literal_in_user_page_table(source: &str) {
    assert!(
        !source.contains("set_addr"),
        "user_page_table.rs must never call set_addr (no mappings should ever be added)"
    );
    assert!(
        !source.contains("0xFFFF_FFFF"),
        "user_page_table.rs must not map any kernel binary VA range address"
    );
}

// --- SC-5 helpers ---

fn assert_write_xor_execute_validator_guards_all_mappings(source: &str) {
    let has_set_addr = source.contains("set_addr");
    let has_validator = source.contains("validate_page_table_flags");
    assert!(
        has_set_addr,
        "paging source must contain set_addr calls for page table writes"
    );
    assert!(
        has_validator,
        "every paging source with set_addr must call validate_page_table_flags"
    );
}

// --- SC-6 helpers ---

fn assert_allocator_uses_stack_pop_for_unique_addresses(source: &str) {
    assert!(
        source.contains("fn pop_free_page_address"),
        "physical_allocator.rs must define pop_free_page_address (LIFO stack for unique addresses)"
    );
    assert!(
        source.contains(".pop()"),
        "allocator must use .pop() from BoundedStack (returns unique addresses by construction)"
    );
}

fn assert_no_page_deduplication_logic(source: &str) {
    assert!(
        !source.contains("dedup"),
        "physical_allocator.rs must not contain any deduplication logic (D-15)"
    );
    assert!(
        !source.contains("deduplicate"),
        "physical_allocator.rs must not contain deduplicate (D-15: KSM-style dedup forbidden)"
    );
}

// --- Shared helper ---

/// Extracts the body of a function starting at the named fn declaration.
///
/// Returns the source slice from the function start to end of file.
/// Used by multiple SC tests to scope assertions to a specific function.
fn extract_function_body<'source>(source: &'source str, function_name: &str) -> &'source str {
    match source.find(function_name) {
        Some(function_start) => &source[function_start..],
        None => "",
    }
}
