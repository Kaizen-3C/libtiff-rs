//! Differential fuzz target for libtiff `TIFFFetchDirectory` (Slice 2). STRUCTURED input: both sides
//! interpret the same raw bytes as diroff/flags/file and parse the IFD directory structure. A
//! mismatch — or a Rust panic — is a libFuzzer crash. ASan on the C side additionally catches
//! memory-safety bugs in the reference itself (the directory-structure integer-overflow / OOB
//! guards: `m = off + size; if m < off || m < size || m > tif_size`).

#![no_main]

use libfuzzer_sys::fuzz_target;

extern "C" {
    fn run_case_c_dir2(line: *const u8, n: usize, outlen: *mut usize) -> *mut u8;
    fn free_case_c_dir2(p: *mut u8);
}

fn run_case_c_safe(data: &[u8]) -> String {
    let mut outlen: usize = 0;
    // SAFETY: run_case_c_dir2 is the verbatim-sliced C reference (cref/_fuzzlib_driver_dir2.c), given
    // a valid pointer+length and returning NULL or a self-allocated buffer sized `outlen`, freed via
    // free_case_c_dir2 right after copying it out.
    unsafe {
        let ptr = run_case_c_dir2(data.as_ptr(), data.len(), &mut outlen as *mut usize);
        if ptr.is_null() {
            return String::new();
        }
        let bytes = std::slice::from_raw_parts(ptr, outlen);
        let s = String::from_utf8_lossy(bytes).into_owned();
        free_case_c_dir2(ptr);
        s
    }
}

fuzz_target!(|data: &[u8]| {
    let c_trace = run_case_c_safe(data);
    let rust_trace = libtiff_rs::dirread::run_bytes_fetch(data);
    assert_eq!(
        c_trace, rust_trace,
        "libtiff TIFFFetchDirectory differential mismatch on input {:?}",
        data
    );
});
