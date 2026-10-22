use std::process::Command;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_authkit-server"))
}

#[test]
fn version_flag_prints_the_package_version() {
    let output = binary().arg("--version").output().expect("run binary");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 output");
    assert_eq!(
        stdout.trim(),
        format!("authkit-server {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn help_flag_describes_the_scaffold() {
    let output = binary().arg("--help").output().expect("run binary");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 output");
    assert!(stdout.contains("Usage: authkit-server"));
    assert!(stdout.contains("not implemented yet"));
}

#[test]
fn unknown_arguments_fail_with_usage() {
    let output = binary().arg("serve").output().expect("run binary");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("utf-8 output");
    assert!(stderr.contains("unknown argument: serve"));
}
