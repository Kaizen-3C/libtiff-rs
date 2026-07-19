//! Differential fuzz target for the libtiff IFD directory-entry reader (Slice 1). One raw byte
//! string per run, treated as a single `E <type> <count> <offset> <flags> <hex>` op-script line and
//! run through both `libtiff_rs::dirread::run_line` (the Rust port) and the verbatim-sliced C
//! reference (via FFI, cref/_fuzzlib_driver_dir.c). A mismatch — or a Rust panic — is a libFuzzer
//! crash. ASan on the C side additionally catches memory-safety bugs in the reference itself
//! (`TIFFReadDirEntryData`'s offset+size-overflow / tif_size bounds — libtiff's OOB CVE surface).

#![no_main]

use libfuzzer_sys::fuzz_target;

extern "C" {
    fn run_case_c_dir(line: *const u8, n: usize, outlen: *mut usize) -> *mut u8;
    fn free_case_c_dir(p: *mut u8);
}

fn run_case_c_safe(line: &[u8]) -> String {
    let mut outlen: usize = 0;
    // SAFETY: run_case_c_dir is the verbatim-sliced C reference (cref/_fuzzlib_driver_dir.c), given
    // a valid pointer+length and always returning either NULL or a buffer it allocated itself sized
    // `outlen`; we free it with the matching free_case_c_dir right after copying it out.
    unsafe {
        let ptr = run_case_c_dir(line.as_ptr(), line.len(), &mut outlen as *mut usize);
        if ptr.is_null() {
            return String::new();
        }
        let bytes = std::slice::from_raw_parts(ptr, outlen);
        let s = String::from_utf8_lossy(bytes).into_owned();
        free_case_c_dir(ptr);
        s
    }
}

fuzz_target!(|data: &[u8]| {
    // STRUCTURED input: both sides interpret the SAME raw bytes as the directory entry's fields
    // (type/count/offset/flags/file) — no text parsing, so the only thing under test is the ported
    // TIFFReadDirEntryByte logic (type dispatch, range validation, the offset+size-overflow / bounds
    // core). ASan on the C side additionally catches memory-safety bugs in the reference itself.
    let c_trace = run_case_c_safe(data);
    let rust_trace = libtiff_rs::dirread::run_bytes(data);
    assert_eq!(
        c_trace, rust_trace,
        "libtiff IFD-reader differential mismatch on input {:?}",
        data
    );
});
