//! AuthKit native server and administrative CLI entry point.
//!
//! The HTTP server, migrations, and administration commands are not implemented yet. This
//! scaffold validates the binary boundary and keeps the documented CLI name stable.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match run(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

fn run(mut args: impl Iterator<Item = String>) -> Result<(), u8> {
    match args.next().as_deref() {
        None | Some("--help" | "-h") => {
            print_help();
            Ok(())
        }
        Some("--version" | "-V") => {
            println!("authkit-server {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(unknown) => {
            eprintln!("error: unknown argument: {unknown}\n");
            print_help();
            Err(2)
        }
    }
}

fn print_help() {
    println!(
        "authkit-server {}\n\
         AuthKit native server (planning scaffold)\n\n\
         Usage: authkit-server [--help | --version]\n\n\
         The HTTP server and administrative commands are not implemented yet.\n\
         See docs/roadmap.md for the implementation milestones.",
        env!("CARGO_PKG_VERSION")
    );
}
