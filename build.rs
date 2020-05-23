extern crate bindgen;

use anyhow::Result;
use std::env;
use std::path::PathBuf;

fn try_main() -> Result<()> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let project_dir = {
        let mut r = PathBuf::from(file!()).canonicalize()?;
        r.pop();
        r
    };

    // Configure C build
    env::set_var(
        "CFLAGS",
        format!(
            "-I{dir}/vendor/xxhash/ {old}",
            dir = project_dir.display(),
            old = env::var("CFLAGS").unwrap_or("".to_string())
        ),
    );

    // Compile xxhash
    cc::Build::new()
        .file("src/xxhash_bindings.c")
        .compile("xxhash");

    // Generate rust bindings
    println!("cargo:rerun-if-changed=src/bindings.h");
    bindgen::Builder::default()
        .clang_arg("-I./vendor/xxhash/")
        .header("src/xxhash_bindings.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .rustfmt_bindings(true)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_dir.join("xxhash_bindings.rs"))
        .expect("Couldn't write bindings!");

    Ok(())
}

fn main() {
    if let Err(er) = try_main() {
        println!("{}", er);
    }
}
