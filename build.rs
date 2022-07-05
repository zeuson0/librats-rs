use std::{env, path::PathBuf};

fn main() -> shadow_rs::SdResult<()> {
    println!("cargo:rustc-link-search=native=/usr/local/lib/librats");
    println!("cargo:rustc-link-lib=dylib=rats_lib");

    println!("cargo:rerun-if-changed=/usr/local/include/librats/api.h");

    let bindings = bindgen::Builder::default()
        .header("/usr/local/include/librats/api.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .derive_debug(true)
        .derive_default(true)
        .derive_partialeq(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    shadow_rs::new()
}
