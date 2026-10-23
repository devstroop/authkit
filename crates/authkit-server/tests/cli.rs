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
fn help_flag_lists_the_serve_command() {
    let output = binary().arg("--help").output().expect("run binary");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 output");
    assert!(stdout.contains("Usage: authkit-server"));
    assert!(stdout.contains("serve"));
}

#[test]
fn unknown_arguments_fail_with_usage() {
    let output = binary().arg("unknown").output().expect("run binary");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("utf-8 output");
    assert!(stderr.contains("unknown argument: unknown"));
}

#[test]
fn serve_fails_closed_without_an_issuer() {
    let output = binary()
        .arg("serve")
        .env_remove("AUTHKIT_ISSUER")
        .env_remove("DATABASE_URL")
        .env("AUTHKIT_ENV", "production")
        .env("AUTHKIT_DATABASE_URL", "sqlite::memory:")
        .output()
        .expect("run binary");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("utf-8 output");
    assert!(stderr.contains("AUTHKIT_ISSUER"));
}

#[test]
fn serve_rejects_http_issuers_in_production() {
    let output = binary()
        .arg("serve")
        .env("AUTHKIT_ENV", "production")
        .env("AUTHKIT_ISSUER", "http://auth.example.com")
        .env("AUTHKIT_DATABASE_URL", "sqlite::memory:")
        .output()
        .expect("run binary");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("utf-8 output");
    assert!(stderr.contains("HTTPS"));
}
