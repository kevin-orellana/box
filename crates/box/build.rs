use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/run/macos_enforcement/bridge.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
        || std::env::var_os("CARGO_FEATURE_KERNEL_POLICY_INTEGRATION").is_none()
    {
        return;
    }
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("build output"));
    let object = output.join("box_endpoint_security.o");
    let archive = output.join("libbox_endpoint_security.a");
    let status = Command::new("/usr/bin/xcrun")
        .args(["clang", "-target"])
        .arg(std::env::var("TARGET").expect("target"))
        .args(["-fblocks", "-std=c11", "-Wall", "-Wextra", "-Werror", "-c"])
        .arg("src/run/macos_enforcement/bridge.c")
        .arg("-o")
        .arg(&object)
        .status()
        .expect("compile Endpoint Security bridge");
    assert!(
        status.success(),
        "Endpoint Security bridge compilation failed"
    );
    let status = Command::new("/usr/bin/xcrun")
        .args(["ar", "crs"])
        .arg(&archive)
        .arg(&object)
        .status()
        .expect("archive Endpoint Security bridge");
    assert!(status.success(), "Endpoint Security bridge archive failed");
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=box_endpoint_security");
    println!("cargo:rustc-link-lib=EndpointSecurity");
    println!("cargo:rustc-link-lib=bsm");
}
