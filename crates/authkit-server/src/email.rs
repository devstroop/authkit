//! Email delivery adapters.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use authkit_core::domain::DomainError;
use authkit_core::domain::email::Email;
use authkit_core::ports::EmailSender;
use base64::Engine;
use native_tls::TlsConnector;

/// Logs email instead of delivering it. Development only.
#[derive(Clone, Copy, Default)]
pub struct DevEmailSender;

impl EmailSender for DevEmailSender {
    fn send(&self, to: &Email, subject: &str, body: &str) -> Result<(), DomainError> {
        tracing::info!(
            target = "authkit.dev.email",
            to = %to.as_str(),
            subject = %subject,
            body = %body,
            "dev-only email"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmtpTlsMode {
    None,
    StartTls,
    Implicit,
}

pub struct SmtpEmailSender {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    from: String,
    tls: SmtpTlsMode,
}

impl SmtpEmailSender {
    pub fn from_env() -> Option<Self> {
        let host = std::env::var("AUTHKIT_SMTP_HOST").ok()?;
        let from = std::env::var("AUTHKIT_SMTP_FROM").ok()?;
        let port = std::env::var("AUTHKIT_SMTP_PORT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(587);
        let tls = match std::env::var("AUTHKIT_SMTP_TLS")
            .unwrap_or_else(|_| "starttls".to_owned())
            .to_ascii_lowercase()
            .as_str()
        {
            "none" => SmtpTlsMode::None,
            "tls" | "implicit" => SmtpTlsMode::Implicit,
            _ => SmtpTlsMode::StartTls,
        };
        Some(Self {
            host,
            port,
            username: std::env::var("AUTHKIT_SMTP_USERNAME").ok(),
            password: std::env::var("AUTHKIT_SMTP_PASSWORD").ok(),
            from,
            tls,
        })
    }
}

enum Stream {
    Plain(TcpStream),
    Tls(native_tls::TlsStream<TcpStream>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

impl EmailSender for SmtpEmailSender {
    fn send(&self, to: &Email, subject: &str, body: &str) -> Result<(), DomainError> {
        smtp_send(self, to.as_str(), subject, body).map_err(|error| {
            DomainError::new(
                authkit_core::domain::ErrorCode::Internal,
                format!("email delivery failed: {error}"),
            )
        })
    }
}

fn smtp_send(sender: &SmtpEmailSender, to: &str, subject: &str, body: &str) -> Result<(), String> {
    let timeout = Duration::from_secs(30);
    let connector = TlsConnector::new().map_err(|e| e.to_string())?;

    let tcp = TcpStream::connect((sender.host.as_str(), sender.port)).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;

    let mut stream = if sender.tls == SmtpTlsMode::Implicit {
        Stream::Tls(
            connector
                .connect(&sender.host, tcp)
                .map_err(|e| e.to_string())?,
        )
    } else {
        Stream::Plain(tcp)
    };

    read_response(&mut stream, 220)?;
    ehlo(&mut stream, &sender.host)?;

    if sender.tls == SmtpTlsMode::StartTls {
        write_line(&mut stream, "STARTTLS")?;
        read_response(&mut stream, 220)?;
        let tcp = match stream {
            Stream::Plain(tcp) => tcp,
            _ => return Err("unexpected stream state".to_owned()),
        };
        stream = Stream::Tls(
            connector
                .connect(&sender.host, tcp)
                .map_err(|e| e.to_string())?,
        );
        ehlo(&mut stream, &sender.host)?;
    }

    if let (Some(username), Some(password)) = (&sender.username, &sender.password) {
        let credentials = format!("\u{0}{}\u{0}{}", username, password);
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
        write_line(&mut stream, &format!("AUTH PLAIN {}", encoded))?;
        read_response(&mut stream, 235)?;
    }

    write_line(&mut stream, &format!("MAIL FROM:<{}>", sender.from))?;
    read_response(&mut stream, 250)?;
    write_line(&mut stream, &format!("RCPT TO:<{}>", to))?;
    read_response(&mut stream, 250)?;
    write_line(&mut stream, "DATA")?;
    read_response(&mut stream, 354)?;

    let subject = subject.replace(['\r', '\n'], " ");
    writeln!(stream, "From: {}", sender.from).map_err(|e| e.to_string())?;
    writeln!(stream, "To: {}", to).map_err(|e| e.to_string())?;
    writeln!(stream, "Subject: {}", subject).map_err(|e| e.to_string())?;
    writeln!(stream, "MIME-Version: 1.0").map_err(|e| e.to_string())?;
    writeln!(stream, "Content-Type: text/plain; charset=utf-8").map_err(|e| e.to_string())?;
    writeln!(stream).map_err(|e| e.to_string())?;
    for line in body.lines() {
        let line = if line.starts_with('.') {
            format!(".{}", line)
        } else {
            line.to_owned()
        };
        writeln!(stream, "{}", line).map_err(|e| e.to_string())?;
    }
    write_line(&mut stream, ".")?;
    read_response(&mut stream, 250)?;
    let _ = write_line(&mut stream, "QUIT");
    Ok(())
}

fn ehlo(stream: &mut Stream, host: &str) -> Result<(), String> {
    write_line(stream, &format!("EHLO {}", host))?;
    read_response(stream, 250)
}

fn write_line(stream: &mut Stream, line: &str) -> Result<(), String> {
    stream
        .write_all(format!("{}\r\n", line).as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())
}

fn read_response(stream: &mut impl Read, expected: u16) -> Result<(), String> {
    let mut line = String::new();
    loop {
        line.clear();
        let mut byte = [0_u8; 1];
        loop {
            let count = stream.read(&mut byte).map_err(|e| e.to_string())?;
            if count == 0 {
                return Err("unexpected end of SMTP response".to_owned());
            }
            line.push(byte[0] as char);
            if byte[0] == b'\n' {
                break;
            }
        }
        if line.len() >= 4 {
            let code = line[..3].parse::<u16>().unwrap_or(0);
            let separator = line.as_bytes().get(3).copied().unwrap_or(b' ');
            if separator == b' ' {
                if code != expected {
                    return Err(format!("SMTP error: {}", line.trim()));
                }
                return Ok(());
            }
        }
    }
}
