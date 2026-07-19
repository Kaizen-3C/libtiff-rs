//! Assembles cref/legacy_fuzzlib.c (shim + verbatim 4-codec decoder slice + the FFI wrapper)
//! from the upstream libtiff 4.7.0 tarball, the same way scripts/regen_goldens.sh does for the
//! op-script driver, and compiles it into this fuzz binary with matching ASan instrumentation
//! so both sides of the differential contribute to libFuzzer's coverage feedback.
//!
//! Requires TIFF_SRC (the unpacked tiff-4.7.0/libtiff tree) to be set — regen_goldens.sh's
//! tarball extraction (cref/_build/tiff-4.7.0/libtiff) works; run that once first if
//! cref/_build is empty.

use std::path::Path;
use std::process::Command;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let crate_root = Path::new(&manifest_dir).parent().unwrap();
    let cref = crate_root.join("cref");
    let out_dir = std::env::var("OUT_DIR").unwrap();

    let tiff_src = std::env::var("TIFF_SRC").unwrap_or_else(|_| {
        crate_root.join("cref/_build/tiff-4.7.0/libtiff").display().to_string()
    });
    assert!(
        Path::new(&tiff_src).join("tif_lzw.c").is_file(),
        "TIFF_SRC ({tiff_src}) doesn't contain tif_lzw.c — run scripts/regen_goldens.sh once \
         first to extract the pinned tarball, or set TIFF_SRC explicitly"
    );

    let status = Command::new("python3")
        .arg(cref.join("assemble_fuzzlib.py"))
        .env("TIFF_SRC", &tiff_src)
        .env("OUT", &out_dir)
        .status()
        .expect("run cref/assemble_fuzzlib.py (needs python3 on PATH)");
    assert!(status.success(), "assemble_fuzzlib.py failed");

    // IFD entry-reader fuzzlib (Slice 1): distinct in-process symbol (run_case_c_dir) over the
    // verbatim tif_dirread.c slice — the integer-overflow/OOB CVE surface.
    let status_dir = Command::new("python3")
        .arg(cref.join("assemble_fuzzlib_dir.py"))
        .env("TIFF_SRC", &tiff_src)
        .env("OUT", &out_dir)
        .status()
        .expect("run cref/assemble_fuzzlib_dir.py (needs python3 on PATH)");
    assert!(status_dir.success(), "assemble_fuzzlib_dir.py failed");

    // TIFFFetchDirectory fuzzlib (Slice 2): reuse assemble_dir2.py with the fuzzlib driver.
    let status_dir2 = Command::new("python3")
        .arg(cref.join("assemble_dir2.py"))
        .env("TIFF_SRC", &tiff_src)
        .env("OUT", &out_dir)
        .env("DRIVER", "_fuzzlib_driver_dir2.c")
        .status()
        .expect("run cref/assemble_dir2.py (fuzzlib variant)");
    assert!(status_dir2.success(), "assemble_dir2.py (fuzzlib) failed");

    for f in [
        "_prelude.c", "_fuzzlib_driver.c", "assemble_fuzzlib.py",
        "_prelude_dir.c", "_fuzzlib_driver_dir.c", "assemble_fuzzlib_dir.py",
        "_prelude_dir2.c", "_fuzzlib_driver_dir2.c", "assemble_dir2.py",
    ] {
        println!("cargo:rerun-if-changed={}", cref.join(f).display());
    }

    // fuzzer-no-link is a clang-only -fsanitize= value; the `cc` crate's default `cc` alias may
    // resolve to gcc, which rejects it, so force clang explicitly.
    cc::Build::new()
        .compiler("clang")
        .file(Path::new(&out_dir).join("legacy_fuzzlib.c"))
        .flag("-fsanitize=address,fuzzer-no-link")
        .flag("-g")
        .flag("-O1")
        .compile("tiff_fuzzlib");
    cc::Build::new()
        .compiler("clang")
        .file(Path::new(&out_dir).join("legacy_fuzzlib_dir.c"))
        .flag("-fsanitize=address,fuzzer-no-link")
        .flag("-g")
        .flag("-O1")
        .compile("tiff_fuzzlib_dir");
    cc::Build::new()
        .compiler("clang")
        .file(Path::new(&out_dir).join("legacy_fuzzlib_dir2.c"))
        .flag("-fsanitize=address,fuzzer-no-link")
        .flag("-g")
        .flag("-O1")
        .compile("tiff_fuzzlib_dir2");
}
