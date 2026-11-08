//! Link settings for the binaries of this package. Most of a process's RSS at rest is code that the kernel maps in 64 KB
//! windows, so one call to a function also maps its neighbors. `hot-functions.txt` lists the functions that run, in
//! first-call order, so they sit together. A stale list costs memory only: names it does not find are skipped.
//! Regenerate it with `scripts/hot-functions.sh`.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=hot-functions.txt");
    let target = std::env::var("TARGET").unwrap_or_default();
    if target == "x86_64-unknown-linux-gnu" {
        let list = format!("{}/hot-functions.txt", std::env::var("CARGO_MANIFEST_DIR").unwrap());
        for args in ["bins", "examples"] {
            println!("cargo:rustc-link-arg-{args}=-Wl,--symbol-ordering-file={list},--no-warn-symbol-ordering,-z,pack-relative-relocs");
        }
    }
}
