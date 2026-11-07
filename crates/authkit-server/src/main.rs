//! AuthKit native server and administrative CLI entry point.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use authkit_server::config::Config;
use authkit_server::telemetry::init_tracing;
use authkit_store::SqlStore;

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
        Some("audit") => match args.next().as_deref() {
            Some("export") => audit_export(args.collect()),
            _ => {
                eprintln!("error: expected 'audit export'\n");
                print_help();
                Err(2)
            }
        },
        Some(unknown) => {
            eprintln!("error: unknown argument: {unknown}\n");
            print_help();
            Err(2)
        }
    }
}

fn audit_export(args: Vec<String>) -> Result<(), u8> {
    let mut org: Option<String> = None;
    let mut limit: i64 = 1000;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--org" => {
                if i + 1 >= args.len() {
                    eprintln!("error: --org requires a value");
                    return Err(2);
                }
                org = Some(args[i + 1].clone());
                i += 2;
            }
            "--limit" => {
                if i + 1 >= args.len() {
                    eprintln!("error: --limit requires a value");
                    return Err(2);
                }
                limit = args[i + 1].parse().unwrap_or(1000);
                i += 2;
            }
            other => {
                eprintln!("error: unknown argument: {other}");
                return Err(2);
            }
        }
    }

    let config = Config::from_env().map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    let url = config.database().url().to_owned();
    let max_connections = config.database().max_connections();
    let store = SqlStore::connect(&url, max_connections).map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            eprintln!("error: {e}");
            1
        })?;

    runtime.block_on(async {
        use sqlx::Row;
        let mut sql = String::from(
            "SELECT id, org_id, actor_type, actor_id, action, target, occurred_at, attributes FROM audit_event",
        );
        if org.is_some() {
            sql.push_str(" WHERE org_id = ?");
        }
        sql.push_str(" ORDER BY occurred_at, id LIMIT ?");
        let mut query = sqlx::query(&sql);
        if let Some(org) = &org {
            query = query.bind(org);
        }
        query = query.bind(limit);
        let rows = query.fetch_all(store.pool()).await.map_err(|e| {
            eprintln!("error: {e}");
            1u8
        })?;
        for row in rows {
            let id: String = row.get("id");
            let org_id: Option<String> = row.get("org_id");
            let actor_type: String = row.get("actor_type");
            let actor_id: Option<String> = row.get("actor_id");
            let action: String = row.get("action");
            let target: Option<String> = row.get("target");
            let occurred_at: i64 = row.get("occurred_at");
            let attributes: String = row.get("attributes");
            let obj = serde_json::json!({
                "id": id,
                "org_id": org_id,
                "actor_type": actor_type,
                "actor_id": actor_id,
                "action": action,
                "target": target,
                "occurred_at": occurred_at,
                "attributes": serde_json::from_str::<serde_json::Value>(&attributes).unwrap_or(serde_json::json!({})),
            });
            println!("{}", obj);
        }
        Ok(())
    })
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
           serve          Start the HTTP server using environment configuration\n\
           audit export   Export audit events as JSONL\n\n\
         Options:\n\
           -h, --help       Print this help\n\
           -V, --version    Print the version\n\n\
         See docs/development.md for configuration variables.",
        env!("CARGO_PKG_VERSION")
    );
}
