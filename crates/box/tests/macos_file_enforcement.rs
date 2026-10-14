//! Ordinary builds must not activate experimental native enforcement implicitly.
#![cfg(target_os = "macos")]

use std::process::Command;

#[path = "support/bounded_output.rs"]
mod bounded_output;

fn run(selection: &str) -> (tempfile::TempDir, std::process::Output) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let quote =
        |path: &std::path::Path| toml::Value::String(path.display().to_string()).to_string();
    let config = format!(
        "name = \"native-opt-in\"\nbox_dir = {}\n{selection}\n[agent]\ncommand = [\"/bin/echo\", \"WORKLOAD_STARTED\"]\nworkspace = {}\n",
        quote(&root.join("box")),
        quote(&workspace),
    );
    let path = root.join("box.toml");
    std::fs::write(&path, config).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box"));
    command
        .args(["run", "--config"])
        .arg(path)
        .env("HOME", &root)
        .current_dir(&workspace);
    let output = bounded_output::bounded_output(command);
    (directory, output)
}

#[test]
fn ordinary_build_does_not_require_native_enforcement() {
    for selection in [
        "",
        "[experimental-features]\nnative-filesystem-policy = false",
    ] {
        let (_directory, output) = run(selection);
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("WORKLOAD_STARTED"),
            "{output:?}"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("macOS file enforcement ready"),
            "{output:?}"
        );
    }
}

#[test]
fn opted_in_unsigned_build_refuses_before_workload_start() {
    let (_directory, output) = run("[experimental-features]\nnative-filesystem-policy = true");
    assert!(!output.status.success(), "{output:?}");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("WORKLOAD_STARTED"),
        "{output:?}"
    );
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    if cfg!(all(
        target_os = "macos",
        feature = "kernel-policy-integration"
    )) {
        assert!(
            diagnostic.contains("macOS file enforcement could not start"),
            "{output:?}"
        );
    } else {
        assert!(
            diagnostic.contains("experimental feature `native-filesystem-policy` requires"),
            "{output:?}"
        );
    }
}
