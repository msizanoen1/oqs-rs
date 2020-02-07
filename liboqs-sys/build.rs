use std::env;
use std::path::PathBuf;

fn env(name: &str) -> Option<String> {
    let target = env::var("TARGET").unwrap().to_uppercase().replace("-", "_");
    println!("cargo:rerun-if-env-changed={}_{}", target, name);
    env::var(&format!("{}_{}", target, name))
        .or_else(|_| {
            println!("cargo:rerun-if-env-changed={}", name);
            env::var(name)
        })
        .ok()
}

fn main() {
    let host = env::var("HOST").unwrap();
    let target = env::var("TARGET").unwrap();
    let is_cross = host != target;
    let prefix = PathBuf::from(env("LIBOQS_PREFIX").expect("Please set LIBOQS_PREFIX"));
    println!(
        "cargo:rustc-link-search=native={}",
        prefix.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=oqs");
    let include = prefix.join("include");
    let outpath = PathBuf::from(env::var("OUT_DIR").unwrap()).join("generated.rs");
    let bindgen = if is_cross {
        let target = if target.starts_with("riscv") {
            let mut split = target.split("-");
            let arch = split.next().unwrap();
            let rest = split.collect::<Vec<_>>().join("-");
            let bitness = &arch[5..7];
            format!("riscv{}-{}", bitness, rest)
        } else {
            target
        };
        bindgen::builder()
            .clang_arg(format!(
                "--sysroot={}",
                env("LIBOQS_CROSS_SYSROOT").expect("Please set LIBOQS_CROSS_SYSROOT")
            ))
            .clang_arg(format!("--target={}", target))
    } else {
        bindgen::builder()
    };
    bindgen
        .header(include.join("oqs").join("oqs.h").to_string_lossy())
        .clang_arg(format!("-I{}", include.display()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .unwrap()
        .write_to_file(&outpath)
        .unwrap();
}
