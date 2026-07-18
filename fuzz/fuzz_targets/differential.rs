//! Differential fuzz target: one raw byte string per run, treated as a single op-script line
//! (`P`/`T`/`N`/`L <args...> <hex>`) and run through both `libtiff_rs::driver_core::run_line`
//! (the Rust port, same shared interpreter `differential_driver` uses) and the verbatim-sliced
//! C reference (via FFI, cref/_fuzzlib_driver.c). A mismatch — or a Rust panic — is a libFuzzer
//! crash with a minimized repro.

#![no_main]

use libfuzzer_sys::fuzz_target;

extern "C" {
    fn run_case_c(line: *const u8, n: usize, outlen: *mut usize) -> *mut u8;
    fn free_case_c(p: *mut u8);
}

fn run_case_c_safe(line: &[u8]) -> String {
    let mut outlen: usize = 0;
    // SAFETY: run_case_c is the verbatim-sliced C reference (cref/_fuzzlib_driver.c), given a
    // valid pointer+length and always returning either NULL or a buffer it allocated itself
    // sized `outlen`; we free it with the matching free_case_c right after copying it out.
    unsafe {
        let ptr = run_case_c(line.as_ptr(), line.len(), &mut outlen as *mut usize);
        if ptr.is_null() {
            return String::new();
        }
        let bytes = std::slice::from_raw_parts(ptr, outlen);
        let s = String::from_utf8_lossy(bytes).into_owned();
        free_case_c(ptr);
        s
    }
}

fuzz_target!(|data: &[u8]| {
    // Same reasoning as the libpcap-rs/libogg-rs fuzz targets: convert once, feed the SAME
    // bytes to both sides, so an invalid-UTF-8 input can't "diverge" purely from encoding
    // handling rather than any real behavioral difference in the ported logic.
    let line = String::from_utf8_lossy(data).into_owned();
    let c_trace = run_case_c_safe(line.as_bytes());
    let rust_trace = libtiff_rs::driver_core::run_line(&line);
    assert_eq!(
        c_trace, rust_trace,
        "libtiff differential mismatch on input {:?} (normalized: {:?})",
        data, line
    );
});
