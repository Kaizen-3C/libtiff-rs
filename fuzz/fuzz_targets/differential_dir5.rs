//! Differential fuzz target for libtiff strip/tile geometry counts (Slice 5): `TIFFNumberOfStrips`
//! and `TIFFNumberOfTiles`. STRUCTURED input: both sides interpret the same raw bytes as the
//! directory geometry fields and run the howmany ceil-division + `_TIFFMultiply32` overflow guards.
//! A mismatch — or a Rust panic (debug-overflow, divide-by-zero) — is a libFuzzer crash. This is the
//! strip/tile-count integer-overflow surface that sizes the offset/bytecount arrays and decode
//! buffers, so a silent count divergence is exactly the under-allocation → OOB precursor.

#![no_main]

use libfuzzer_sys::fuzz_target;

extern "C" {
    fn run_case_c_dir5(line: *const u8, n: usize, outlen: *mut usize) -> *mut u8;
    fn free_case_c_dir5(p: *mut u8);
}

fn run_case_c_safe(data: &[u8]) -> String {
    let mut outlen: usize = 0;
    // SAFETY: run_case_c_dir5 is the verbatim-sliced C reference (cref/_fuzzlib_driver_dir5.c), given
    // a valid pointer+length and returning NULL or a self-allocated buffer sized `outlen`, freed via
    // free_case_c_dir5 right after copying it out.
    unsafe {
        let ptr = run_case_c_dir5(data.as_ptr(), data.len(), &mut outlen as *mut usize);
        if ptr.is_null() {
            return String::new();
        }
        let bytes = std::slice::from_raw_parts(ptr, outlen);
        let s = String::from_utf8_lossy(bytes).into_owned();
        free_case_c_dir5(ptr);
        s
    }
}

fuzz_target!(|data: &[u8]| {
    let c_trace = run_case_c_safe(data);
    let rust_trace = libtiff_rs::geometry::run_bytes_geom(data);
    assert_eq!(
        c_trace, rust_trace,
        "libtiff strip/tile geometry-count differential mismatch on input {:?}",
        data
    );
});
