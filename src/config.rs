use std::{net::IpAddr, path::PathBuf};

use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use serde::Serialize;

const MAX_ICE_SERVERS: usize = 8;

#[derive(Clone, Debug, Serialize)]
pub struct RtcIceServer {
    pub urls: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum MediaMode {
    Forward,
    Stun,
    Turn,
    Disabled,
}

impl MediaMode {
    pub const fn enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

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

    /// Write application logs to this file in addition to stdout.
    #[arg(long)]
    pub log_file: Option<PathBuf>,

    /// Daemonize: detach from the terminal and run in the background.
    #[arg(long)]
    pub daemon: bool,

    #[arg(long, default_value = "data")]
    pub data_dir: PathBuf,

    /// Live media transport: built-in forwarding, STUN, TURN, or disabled.
    #[arg(long, value_enum, default_value = "forward")]
    pub media_mode: MediaMode,

    /// UDP port advertised by the built-in media forwarder.
    #[arg(long, default_value = "7882", value_parser = parse_media_port)]
    pub media_port: u16,

    /// Public IP advertised by the built-in media forwarder.
    #[arg(long)]
    pub media_address: Option<IpAddr>,

    /// STUN or TURN URL used by browser WebRTC peers; may be repeated.
    #[arg(long = "ice-server", value_parser = parse_ice_server)]
    pub ice_servers: Vec<String>,

    /// Username supplied to configured TURN servers.
    #[arg(long, requires = "ice_servers")]
    pub turn_username: Option<String>,

    /// Credential supplied to configured TURN servers.
    #[arg(long, requires = "ice_servers")]
    pub turn_credential: Option<String>,
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

    pub fn rtc_ice_servers(&self) -> Vec<RtcIceServer> {
        self.ice_servers
            .iter()
            .map(|url| {
                let is_turn = url.starts_with("turn:") || url.starts_with("turns:");
                RtcIceServer {
                    urls: url.clone(),
                    username: if is_turn {
                        self.turn_username.clone()
                    } else {
                        None
                    },
                    credential: if is_turn {
                        self.turn_credential.clone()
                    } else {
                        None
                    },
                }
            })
            .collect()
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
        if self.ice_servers.len() > MAX_ICE_SERVERS {
            bail!("no more than {MAX_ICE_SERVERS} --ice-server values may be configured");
        }
        if self.turn_username.is_some() != self.turn_credential.is_some() {
            bail!("--turn-username and --turn-credential must be provided together");
        }
        if self
            .turn_username
            .as_deref()
            .is_some_and(|value| value.is_empty() || value.len() > 256)
            || self
                .turn_credential
                .as_deref()
                .is_some_and(|value| value.is_empty() || value.len() > 256)
        {
            bail!("TURN credentials must contain 1-256 characters");
        }
        match self.media_mode {
            MediaMode::Forward => {
                if !self.ice_servers.is_empty()
                    || self.turn_username.is_some()
                    || self.turn_credential.is_some()
                {
                    bail!("--media-mode forward does not use STUN or TURN options");
                }
            }
            MediaMode::Stun => {
                if self.ice_servers.is_empty()
                    || !self
                        .ice_servers
                        .iter()
                        .all(|url| url.starts_with("stun:") || url.starts_with("stuns:"))
                {
                    bail!("--media-mode stun requires at least one STUN --ice-server URL");
                }
                if self.turn_username.is_some() || self.turn_credential.is_some() {
                    bail!("--media-mode stun does not accept TURN credentials");
                }
            }
            MediaMode::Turn => {
                if self.ice_servers.is_empty()
                    || !self
                        .ice_servers
                        .iter()
                        .all(|url| url.starts_with("turn:") || url.starts_with("turns:"))
                {
                    bail!("--media-mode turn requires at least one TURN --ice-server URL");
                }
                if self.turn_username.is_none() || self.turn_credential.is_none() {
                    bail!("--media-mode turn requires --turn-username and --turn-credential");
                }
            }
            MediaMode::Disabled => {
                if !self.ice_servers.is_empty()
                    || self.turn_username.is_some()
                    || self.turn_credential.is_some()
                {
                    bail!("--media-mode disabled does not accept STUN or TURN options");
                }
            }
        }
        if self.media_mode != MediaMode::Forward && self.media_address.is_some() {
            bail!("--media-address is only valid with --media-mode forward");
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

fn parse_media_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|_| format!("invalid media port number '{value}'"))?;
    if port == 0 {
        return Err("media port must be in range 1-65535".to_owned());
    }
    Ok(port)
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

fn parse_ice_server(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 512
        || value.chars().any(char::is_whitespace)
        || !["stun:", "stuns:", "turn:", "turns:"]
            .iter()
            .any(|prefix| value.starts_with(prefix))
    {
        return Err("ICE server must be a valid stun:, stuns:, turn:, or turns: URL".to_owned());
    }
    Ok(value.to_owned())
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

    #[test]
    fn validates_and_formats_ice_servers() {
        let config = AppConfig::try_parse_from([
            "share2me",
            "--media-mode",
            "turn",
            "--ice-server",
            "turns:turn.example.com:5349?transport=tcp",
            "--turn-username",
            "alice",
            "--turn-credential",
            "secret",
        ])
        .unwrap();
        config.validate().unwrap();
        let servers = config.rtc_ice_servers();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].username.as_deref(), Some("alice"));
        assert!(
            AppConfig::try_parse_from(["share2me", "--ice-server", "https://turn.example.com"])
                .is_err()
        );
    }

    #[test]
    fn media_mode_defaults_to_forward_and_validates_dependencies() {
        let forward = AppConfig::try_parse_from(["share2me"]).unwrap();
        forward.validate().unwrap();
        assert_eq!(forward.media_mode, MediaMode::Forward);

        let stun = AppConfig::try_parse_from([
            "share2me",
            "--media-mode",
            "stun",
            "--ice-server",
            "stun:stun.example.com:3478",
        ])
        .unwrap();
        stun.validate().unwrap();

        let missing_stun = AppConfig::try_parse_from(["share2me", "--media-mode", "stun"]).unwrap();
        assert!(missing_stun.validate().is_err());
        let missing_turn = AppConfig::try_parse_from([
            "share2me",
            "--media-mode",
            "turn",
            "--ice-server",
            "turn:turn.example.com:3478",
        ])
        .unwrap();
        assert!(missing_turn.validate().is_err());
    }
}
