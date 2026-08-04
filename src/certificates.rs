use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufReader, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use axum_server::tls_rustls::RustlsConfig;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tokio::sync::{RwLock, watch};
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

pub type Challenges = Arc<RwLock<HashMap<String, String>>>;

#[derive(Clone, Debug)]
pub struct CertificateConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub domain: String,
    pub use_acme: bool,
    pub email: Option<String>,
    pub staging: bool,
    pub verbose: bool,
    pub work_dir: PathBuf,
}

pub async fn restore_challenges(work_dir: &Path) -> Challenges {
    let path = work_dir.join("challenges.json");
    let challenges = match tokio::fs::read(&path).await {
        Ok(bytes) => match serde_json::from_slice::<HashMap<String, String>>(&bytes) {
            Ok(challenges) => challenges,
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "failed to parse persisted ACME challenges");
                HashMap::new()
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
        Err(error) => {
            tracing::warn!(%error, path = %path.display(), "failed to restore ACME challenges");
            HashMap::new()
        }
    };
    if !challenges.is_empty() {
        tracing::info!(
            count = challenges.len(),
            "restored persisted ACME challenges"
        );
    }
    Arc::new(RwLock::new(challenges))
}

pub async fn provision(
    config: &CertificateConfig,
    challenges: &Challenges,
    renewal_threshold_days: i64,
) -> Result<bool> {
    if !needs_renewal(&config.cert_path, &config.key_path, renewal_threshold_days) {
        tracing::info!(
            threshold_days = renewal_threshold_days,
            "existing certificate is still valid"
        );
        return Ok(false);
    }

    if config.use_acme {
        tracing::info!(domain = %config.domain, staging = config.staging, "requesting Let's Encrypt certificate");
        match request_acme_certificate(config, challenges).await {
            Ok(()) => {
                tracing::info!(domain = %config.domain, "Let's Encrypt certificate obtained");
                return Ok(true);
            }
            Err(error) => {
                tracing::error!(%error, "ACME certificate request failed");
                tracing::warn!("falling back to a self-signed certificate");
            }
        }
    }

    generate_self_signed(config)?;
    tracing::info!(domain = %config.domain, "generated self-signed TLS certificate");
    Ok(true)
}

pub async fn renewal_loop(
    config: CertificateConfig,
    challenges: Challenges,
    tls: RustlsConfig,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(12 * 60 * 60)) => {
                match provision(&config, &challenges, 30).await {
                    Ok(true) => {
                        match tls.reload_from_pem_file(&config.cert_path, &config.key_path).await {
                            Ok(()) => tracing::info!("live TLS configuration reloaded"),
                            Err(error) => tracing::error!(%error, "TLS reload failed"),
                        }
                    }
                    Ok(false) => {}
                    Err(error) => tracing::error!(%error, "certificate renewal check failed"),
                }
            }
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

pub fn needs_renewal(cert_path: &Path, key_path: &Path, threshold_days: i64) -> bool {
    if !cert_path.is_file() || !key_path.is_file() {
        return true;
    }
    certificate_expiry(cert_path).is_none_or(|expiry| {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        expiry.saturating_sub(now) < threshold_days.saturating_mul(86_400)
    })
}

fn certificate_expiry(cert_path: &Path) -> Option<i64> {
    let file = File::open(cert_path).ok()?;
    let mut reader = BufReader::new(file);
    let certificate = rustls_pemfile::certs(&mut reader).next()?.ok()?;
    let (_, parsed) = parse_x509_certificate(certificate.as_ref()).ok()?;
    Some(parsed.validity().not_after.timestamp())
}

fn generate_self_signed(config: &CertificateConfig) -> Result<()> {
    let mut names = vec![
        config.domain.clone(),
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
    ];
    names.sort();
    names.dedup();

    let mut params = CertificateParams::new(names).context("creating certificate parameters")?;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(3650);
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::OrganizationName, "Share2Me");
    distinguished_name.push(DnType::CommonName, config.domain.clone());
    params.distinguished_name = distinguished_name;

    let key_pair = KeyPair::generate().context("generating certificate key")?;
    let certificate = params
        .self_signed(&key_pair)
        .context("signing self-signed certificate")?;
    let private_key = Zeroizing::new(key_pair.serialize_pem());
    write_certificate_pair(
        &config.cert_path,
        certificate.pem().as_bytes(),
        &config.key_path,
        private_key.as_bytes(),
    )
}

async fn request_acme_certificate(
    config: &CertificateConfig,
    challenges: &Challenges,
) -> Result<()> {
    let email = config
        .email
        .as_deref()
        .filter(|email| !email.is_empty())
        .context("--email is required with --acme")?;
    fs::create_dir_all(&config.work_dir).context("creating ACME work directory")?;

    let directory = if config.staging {
        LetsEncrypt::Staging
    } else {
        LetsEncrypt::Production
    };
    let account_path = config.work_dir.join(if config.staging {
        "account-staging.json"
    } else {
        "account-production.json"
    });
    let account = load_or_create_account(&account_path, email, directory).await?;
    let identifiers = [Identifier::Dns(config.domain.clone())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("creating ACME order")?;
    let mut active_tokens = Vec::new();

    let issuance = async {
        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authorization = result.context("fetching ACME authorization")?;
                match authorization.status {
                    AuthorizationStatus::Valid => continue,
                    AuthorizationStatus::Pending => {}
                    status => bail!("unexpected ACME authorization status: {status:?}"),
                }

                let mut challenge = authorization
                    .challenge(ChallengeType::Http01)
                    .context("ACME server did not offer an HTTP-01 challenge")?;
                let token = challenge.token.clone();
                let key_authorization = challenge.key_authorization().as_str().to_owned();
                set_challenge(
                    &config.work_dir,
                    challenges,
                    &token,
                    Some(key_authorization),
                )
                .await?;
                active_tokens.push(token.clone());
                if config.verbose {
                    tracing::info!(%token, "ACME HTTP-01 challenge registered");
                }
                challenge
                    .set_ready()
                    .await
                    .context("starting HTTP-01 challenge")?;
            }
        }

        let retry = RetryPolicy::new()
            .initial_delay(Duration::from_secs(1))
            .timeout(Duration::from_secs(120));
        let status = order
            .poll_ready(&retry)
            .await
            .context("waiting for ACME validation")?;
        if status != OrderStatus::Ready {
            bail!("ACME order did not become ready: {status:?}");
        }
        let private_key = Zeroizing::new(order.finalize().await.context("finalizing ACME order")?);
        let certificate = order
            .poll_certificate(&retry)
            .await
            .context("downloading ACME certificate")?;
        Ok::<_, anyhow::Error>((certificate, private_key))
    }
    .await;

    for token in active_tokens {
        if let Err(error) = set_challenge(&config.work_dir, challenges, &token, None).await {
            tracing::warn!(%error, %token, "failed to remove persisted ACME challenge");
        }
    }

    let (certificate, private_key) = issuance?;
    write_certificate_pair(
        &config.cert_path,
        certificate.as_bytes(),
        &config.key_path,
        private_key.as_bytes(),
    )
}

async fn load_or_create_account(
    path: &Path,
    email: &str,
    directory: LetsEncrypt,
) -> Result<Account> {
    if let Ok(bytes) = tokio::fs::read(path).await {
        let credentials: AccountCredentials =
            serde_json::from_slice(&bytes).context("parsing saved ACME account")?;
        return Account::builder()?
            .from_credentials(credentials)
            .await
            .context("restoring ACME account");
    }

    let contact = format!("mailto:{email}");
    let contacts = [contact.as_str()];
    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &contacts,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory.url().to_owned(),
            None,
        )
        .await
        .context("creating ACME account")?;
    let serialized = Zeroizing::new(serde_json::to_vec_pretty(&credentials)?);
    write_secure_atomic(path, &serialized, 0o600)?;
    Ok(account)
}

async fn set_challenge(
    work_dir: &Path,
    challenges: &Challenges,
    token: &str,
    value: Option<String>,
) -> Result<()> {
    let snapshot = {
        let mut guard = challenges.write().await;
        if let Some(value) = value {
            guard.insert(token.to_owned(), value);
        } else {
            guard.remove(token);
        }
        guard.clone()
    };
    let path = work_dir.join("challenges.json");
    let bytes = serde_json::to_vec_pretty(&snapshot)?;
    tokio::task::spawn_blocking(move || write_secure_atomic(&path, &bytes, 0o600))
        .await
        .context("persisting ACME challenge task")??;
    Ok(())
}

fn write_certificate_pair(
    cert_path: &Path,
    certificate: &[u8],
    key_path: &Path,
    private_key: &[u8],
) -> Result<()> {
    if let Some(parent) = cert_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    // Write the key first so a crash cannot expose it with permissive default permissions.
    write_secure_atomic(key_path, private_key, 0o600)?;
    write_secure_atomic(cert_path, certificate, 0o644)?;
    Ok(())
}

fn write_secure_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid output filename")?;
    let temp_path = path.with_file_name(format!(".{file_name}.{:016x}.tmp", rand::random::<u64>()));
    let mut temp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temp_path)
        .with_context(|| format!("creating {}", temp_path.display()))?;
    let result = (|| -> Result<()> {
        temp.write_all(contents)?;
        temp.sync_all()?;
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(mode))?;
        fs::rename(&temp_path, path)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn self_signed_certificate_is_valid_and_key_is_private() {
        let directory = tempdir().unwrap();
        let config = CertificateConfig {
            cert_path: directory.path().join("cert.pem"),
            key_path: directory.path().join("key.pem"),
            domain: "localhost".to_owned(),
            use_acme: false,
            email: None,
            staging: false,
            verbose: false,
            work_dir: directory.path().join("acme"),
        };
        generate_self_signed(&config).unwrap();
        assert!(!needs_renewal(&config.cert_path, &config.key_path, 30));
        assert_eq!(
            fs::metadata(&config.key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
