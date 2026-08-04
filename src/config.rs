use std::{net::IpAddr, path::PathBuf};

use anyhow::{Result, bail};
use clap::Parser;

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Parser)]
#[command(version, about)]
pub struct AppConfig {
    /// HTTPS port to listen on.
    #[arg(long = "port", default_value = "8443", value_parser = parse_https_port)]
    pub https_port: u16,

    /// HTTP redirect and ACME challenge port; use 0 to disable it.
    #[arg(long, default_value = "8080", value_parser = parse_http_port)]
    pub http_port: u16,

    #[arg(long, default_value = "cert.pem")]
    pub cert: PathBuf,

    #[arg(long, default_value = "key.pem")]
    pub key: PathBuf,

    #[arg(long, default_value = "localhost", value_parser = parse_domain)]
    pub domain: String,

    /// Obtain and renew a Let's Encrypt certificate with HTTP-01.
    #[arg(long)]
    pub acme: bool,

    #[arg(long, requires = "acme")]
    pub email: Option<String>,

    #[arg(long, requires = "acme")]
    pub staging: bool,

    #[arg(long, requires = "acme")]
    pub acme_verbose: bool,

    /// Enter a chroot rooted at the data directory after startup.
    #[arg(long, requires = "drop_user")]
    pub sandbox: bool,

    /// Permanently drop privileges to this system user after binding sockets.
    #[arg(long = "user")]
    pub drop_user: Option<String>,

    #[arg(long)]
    pub http_log: bool,

    #[arg(long, default_value = "data")]
    pub data_dir: PathBuf,
}

impl AppConfig {
    pub fn from_args() -> Result<Self> {
        let config = Self::parse();
        config.validate()?;
        Ok(config)
    }

    pub fn base_url(&self) -> String {
        let host = match self.domain.parse::<IpAddr>() {
            Ok(IpAddr::V6(_)) => format!("[{}]", self.domain),
            _ => self.domain.clone(),
        };
        if self.https_port == 443 {
            format!("https://{host}")
        } else {
            format!("https://{host}:{}", self.https_port)
        }
    }

    fn validate(&self) -> Result<()> {
        if self.acme && self.http_port == 0 {
            bail!("--acme requires --http-port to be greater than 0");
        }
        if self.acme && self.email.as_deref().is_none_or(str::is_empty) {
            bail!("--email is required with --acme");
        }
        if self.data_dir.as_os_str().is_empty() {
            bail!("--data-dir must not be empty");
        }
        if self.cert.as_os_str().is_empty() || self.key.as_os_str().is_empty() {
            bail!("--cert and --key must not be empty");
        }
        Ok(())
    }
}

fn parse_https_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|_| format!("invalid port number '{value}'"))?;
    if port == 0 {
        return Err("HTTPS port must be in range 1-65535".to_owned());
    }
    Ok(port)
}

fn parse_http_port(value: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .map_err(|_| format!("invalid port number '{value}'"))
}

fn parse_domain(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > 253 {
        return Err("domain must contain 1-253 characters".to_owned());
    }
    if value.parse::<IpAddr>().is_ok() || value == "localhost" {
        return Ok(value.to_owned());
    }
    if value.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
    }) {
        return Err("domain must be a valid ASCII hostname or IP address".to_owned());
    }
    Ok(value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_disabling_http() {
        let config = AppConfig::try_parse_from(["share2me", "--http-port", "0"]).unwrap();
        assert_eq!(config.http_port, 0);
    }

    #[test]
    fn rejects_invalid_ports_and_domains() {
        assert!(AppConfig::try_parse_from(["share2me", "--port", "0"]).is_err());
        assert!(AppConfig::try_parse_from(["share2me", "--port", "70000"]).is_err());
        assert!(AppConfig::try_parse_from(["share2me", "--domain", "bad/host"]).is_err());
        assert!(AppConfig::try_parse_from(["share2me", "--sandbox"]).is_err());
    }

    #[test]
    fn formats_ipv6_base_url() {
        let config =
            AppConfig::try_parse_from(["share2me", "--domain", "::1", "--port", "9443"]).unwrap();
        assert_eq!(config.base_url(), "https://[::1]:9443");
    }
}
