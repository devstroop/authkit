//! AuthKit native server and administrative CLI entry point.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use authkit_core::ports::IdGenerator;
use authkit_server::config::Config;
use authkit_server::signing::KeyRing;
use authkit_server::telemetry::init_tracing;
use authkit_store::SqlStore;
use sha2::Digest;
use sha2::Sha256;

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
        Some("migrate") => migrate(),
        Some("backup") => backup(args.collect()),
        Some("restore") => restore(args.collect()),
        Some("bootstrap") => bootstrap(),
        Some("doctor") => doctor(),
        Some("key") => match args.next().as_deref() {
            Some("rotate") => key_rotate(),
            _ => {
                eprintln!("error: expected 'key rotate'\n");
                print_help();
                Err(2)
            }
        },
        Some("audit") => match args.next().as_deref() {
            Some("export") => audit_export(args.collect()),
            Some("prune") => audit_prune(args.collect()),
            Some("verify") => audit_verify(args.collect()),
            _ => {
                eprintln!("error: expected 'audit export', 'audit prune', or 'audit verify'\n");
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

fn migrate() -> Result<(), u8> {
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
    store.migrate().map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    println!("migrated");
    Ok(())
}

fn bootstrap() -> Result<(), u8> {
    migrate()?;
    let config = Config::from_env().map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    let now_ts = authkit_core::domain::time::Timestamp::from_millis(
        (authkit_server::signing::unix_now() as u64) * 1000,
    );
    let url = config.database().url().to_owned();
    let max_connections = config.database().max_connections();
    let store = SqlStore::connect(&url, max_connections).map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;

    let existing =
        authkit_core::ports::SystemAdministratorRepository::list(&store).map_err(|e| {
            eprintln!("error list: {e}");
            1
        })?;
    if existing.is_empty() {
        let email_raw = std::env::var("AUTHKIT_ADMIN_EMAIL").unwrap_or_default();
        let password = std::env::var("AUTHKIT_ADMIN_PASSWORD").unwrap_or_default();
        if email_raw.is_empty() || password.is_empty() {
            eprintln!(
                "error: AUTHKIT_ADMIN_EMAIL and AUTHKIT_ADMIN_PASSWORD are required to bootstrap the first system administrator"
            );
            return Err(1);
        }
        let email = authkit_core::domain::Email::parse(&email_raw).map_err(|e| {
            eprintln!("error: {e}");
            1
        })?;
        let display_name = authkit_core::domain::DisplayName::parse(
            email_raw.split('@').next().unwrap_or("admin"),
        )
        .unwrap_or_else(|_| authkit_core::domain::DisplayName::parse("Admin").expect("valid"));
        let user = if let Some(existing_user) =
            authkit_core::ports::UserRepository::find_by_email(&store, &email).map_err(|e| {
                eprintln!("error find user: {e}");
                1
            })? {
            existing_user
        } else {
            let user = authkit_core::domain::User::new(
                authkit_server::session::SecureIdGenerator
                    .generate::<authkit_core::domain::id::UserEntity>()
                    .expect("id"),
                email.clone(),
                display_name,
                now_ts,
            );
            authkit_core::ports::UserRepository::insert(&store, &user).map_err(|e| {
                eprintln!("error insert user: {e}");
                1
            })?;
            user
        };
        let verifier = authkit_server::password::hash_password(&password).map_err(|e| {
            eprintln!("error: {e}");
            1
        })?;
        let credential = authkit_core::domain::Credential::password(
            authkit_server::session::SecureIdGenerator
                .generate::<authkit_core::domain::id::CredentialEntity>()
                .expect("id"),
            user.id().clone(),
            verifier,
            now_ts,
        );
        authkit_core::ports::CredentialRepository::insert(&store, &credential).map_err(|e| {
            eprintln!("error insert cred: {e}");
            1
        })?;
        let admin = authkit_core::domain::SystemAdministrator::new(
            authkit_server::session::SecureIdGenerator
                .generate::<authkit_core::domain::id::SystemAdministratorEntity>()
                .expect("id"),
            user.id().clone(),
            None,
            now_ts,
        );
        authkit_core::ports::SystemAdministratorRepository::insert(&store, &admin).map_err(
            |e| {
                eprintln!("error insert admin: {e}");
                1
            },
        )?;
        println!("bootstrapped system administrator {}", user.email());
    } else {
        println!("system administrators already exist");
    }

    let now = authkit_server::signing::unix_now();
    let ring = KeyRing::load_or_bootstrap(config.signing_keys(), now).map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    println!("bootstrapped signing key {}", ring.active().kid());
    Ok(())
}

fn key_rotate() -> Result<(), u8> {
    let config = Config::from_env().map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    let now = authkit_server::signing::unix_now();
    let ring = KeyRing::rotate(config.signing_keys(), now).map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    println!("rotated signing key {}", ring.active().kid());
    Ok(())
}

fn doctor() -> Result<(), u8> {
    let config = Config::from_env().map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    println!("config: ok");
    println!("issuer: {}", config.issuer());
    let url = config.database().url().to_owned();
    let max_connections = config.database().max_connections();
    let store = SqlStore::connect(&url, max_connections).map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    store.ping().map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    println!("database: ok");
    let now = authkit_server::signing::unix_now();
    let ring = KeyRing::load_or_bootstrap(config.signing_keys(), now).map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    println!("signing key: ok ({})", ring.active().kid());
    Ok(())
}

fn audit_prune(args: Vec<String>) -> Result<(), u8> {
    let mut days: i64 = 90;
    let mut org: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--days" => {
                if i + 1 >= args.len() {
                    eprintln!("error: --days requires a value");
                    return Err(2);
                }
                days = args[i + 1].parse().unwrap_or(90);
                i += 2;
            }
            "--org" => {
                if i + 1 >= args.len() {
                    eprintln!("error: --org requires a value");
                    return Err(2);
                }
                org = Some(args[i + 1].clone());
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
    let cutoff = (authkit_server::signing::unix_now() as i64 - days * 86400) * 1000;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            eprintln!("error: {e}");
            1
        })?;
    runtime.block_on(async {
        let mut sql = String::from("DELETE FROM audit_event WHERE occurred_at < ?");
        if org.is_some() {
            sql.push_str(" AND org_id = ?");
        }
        let mut query = sqlx::query(&sql).bind(cutoff);
        if let Some(org) = &org {
            query = query.bind(org);
        }
        let result = query.execute(store.pool()).await.map_err(|e| {
            eprintln!("error: {e}");
            1u8
        })?;
        println!("pruned {} audit events", result.rows_affected());
        Ok(())
    })
}

fn audit_verify(args: Vec<String>) -> Result<(), u8> {
    let mut org: Option<String> = None;
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
        let mut sql = String::from("SELECT id, org_id, actor_type, actor_id, action, target, occurred_at, attributes, prev_hash, hash FROM audit_event");
        if org.is_some() { sql.push_str(" WHERE org_id = ?"); }
        sql.push_str(" ORDER BY org_id, occurred_at, id");
        let mut query = sqlx::query(&sql);
        if let Some(org) = &org { query = query.bind(org); }
        let rows = query.fetch_all(store.pool()).await.map_err(|e| { eprintln!("error: {e}"); 1u8 })?;
        let mut current_org: Option<String> = None;
        let mut prev: Option<String> = None;
        let mut failures = 0u64;
        for row in rows {
            let row_org: Option<String> = row.get("org_id");
            if current_org != row_org { current_org = row_org.clone(); prev = None; }
            let id: String = row.get("id");
            let actor_type: String = row.get("actor_type");
            let actor_id: Option<String> = row.get("actor_id");
            let action: String = row.get("action");
            let target: Option<String> = row.get("target");
            let occurred_at: i64 = row.get("occurred_at");
            let attributes: String = row.get("attributes");
            let stored_prev: Option<String> = row.get("prev_hash");
            let stored_hash: Option<String> = row.get("hash");
            if stored_prev != prev { failures += 1; eprintln!("prev_hash mismatch for {id}"); }
            let mut hasher = Sha256::new();
            if let Some(p) = &prev { hasher.update(p.as_bytes()); }
            hasher.update(id.as_bytes());
            if let Some(o) = &row_org { hasher.update(o.as_bytes()); }
            hasher.update(actor_type.as_bytes());
            if let Some(a) = &actor_id { hasher.update(a.as_bytes()); }
            hasher.update(action.as_bytes());
            if let Some(t) = &target { hasher.update(t.as_bytes()); }
            hasher.update(occurred_at.to_string().as_bytes());
            // attributes order as stored (pairs)
            hasher.update(attributes.as_bytes());
            let computed = format!("{:x}", hasher.finalize());
            if stored_hash.as_deref() != Some(computed.as_str()) { failures += 1; eprintln!("hash mismatch for {id}"); }
            prev = stored_hash;
        }
        if failures == 0 { println!("audit chain: ok"); } else { println!("audit chain: {failures} failures"); }
        Ok(())
    })
}

fn backup(args: Vec<String>) -> Result<(), u8> {
    let mut output: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--output" => {
                if i + 1 >= args.len() {
                    eprintln!("error: --output requires a value");
                    return Err(2);
                }
                output = Some(args[i + 1].clone());
                i += 2;
            }
            other => {
                eprintln!("error: unknown argument: {other}");
                return Err(2);
            }
        }
    }
    let output = output.unwrap_or_else(|| "authkit-backup.db".to_owned());
    let config = Config::from_env().map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    if config.database().kind() != authkit_server::config::DatabaseKind::Sqlite {
        eprintln!("error: backup command supports SQLite; use pg_dump for PostgreSQL");
        return Err(1);
    }
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
        sqlx::query("VACUUM INTO ?")
            .bind(&output)
            .execute(store.pool())
            .await
            .map_err(|e| {
                eprintln!("error: {e}");
                1u8
            })?;
        println!("backup written to {output}");
        Ok(())
    })
}

fn restore(args: Vec<String>) -> Result<(), u8> {
    let mut input: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                if i + 1 >= args.len() {
                    eprintln!("error: --input requires a value");
                    return Err(2);
                }
                input = Some(args[i + 1].clone());
                i += 2;
            }
            other => {
                eprintln!("error: unknown argument: {other}");
                return Err(2);
            }
        }
    }
    let input = input.ok_or_else(|| {
        eprintln!("error: --input is required");
        2
    })?;
    let config = Config::from_env().map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    if config.database().kind() != authkit_server::config::DatabaseKind::Sqlite {
        eprintln!("error: restore command supports SQLite; use pg_restore for PostgreSQL");
        return Err(1);
    }
    let url = config.database().url();
    let path = url.strip_prefix("sqlite:").unwrap_or(url);
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_start_matches("//");
    std::fs::copy(&input, path).map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    println!("restored {input} to {path}");
    Ok(())
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
           audit export   Export audit events as JSONL\n\
           audit prune    Prune old audit events\n\
           audit verify   Verify audit hash chains\n\n\
         Options:\n\
           -h, --help       Print this help\n\
           -V, --version    Print the version\n\n\
         See docs/development.md for configuration variables.",
        env!("CARGO_PKG_VERSION")
    );
}
