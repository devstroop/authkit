//! AuthKit native server and administrative CLI entry point.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use authkit_server::config::Config;
use authkit_server::telemetry::init_tracing;

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
        Some("serve") => {
            if let Some(argument) = args.next() {
                eprintln!("error: unexpected argument: {argument}\n");
                print_help();
                return Err(2);
            }
            serve()
        }
        Some(unknown) => {
            eprintln!("error: unknown argument: {unknown}\n");
            print_help();
            Err(2)
        }
    }
}

fn serve() -> Result<(), u8> {
    let config = Config::from_env().map_err(|error| {
        eprintln!("error: {error}");
        1
    })?;
    init_tracing(config.log_format()).map_err(|error| {
        eprintln!("error: failed to initialize logging: {error}");
        1
    })?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            eprintln!("error: failed to create the async runtime: {error}");
            1
        })?;

    runtime
        .block_on(authkit_server::serve(config))
        .map_err(|error| {
            eprintln!("error: {error}");
            1
        })
}

fn print_help() {
    println!(
        "authkit-server {}\n\
         AuthKit native server\n\n\
         Usage: authkit-server <command>\n\n\
         Commands:\n\
           serve    Start the HTTP server using environment configuration\n\n\
         Options:\n\
           -h, --help       Print this help\n\
           -V, --version    Print the version\n\n\
         See docs/development.md for configuration variables.",
        env!("CARGO_PKG_VERSION")
    );
}
