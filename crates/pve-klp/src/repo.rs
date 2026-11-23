//! Access to the static release repository.
//!
//! The repository is untrusted transport: everything fetched from it is
//! checked against the signed manifest before use.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::config::Config;

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("not found in repository: {0}")]
    NotFound(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub trait Repo {
    /// Fetch `rel` (relative to the repository base), at most `max` bytes.
    fn get(&self, rel: &str, max: u64) -> Result<Vec<u8>, RepoError>;
    fn describe(&self) -> String;
}

pub fn open(cfg: &Config) -> Result<Box<dyn Repo>> {
    let r = cfg.repository.trim();
    if r.is_empty() {
        bail!("no repository configured (set `repository` in the config file)");
    }
    if let Some(path) = r.strip_prefix("file://") {
        return Ok(Box::new(FileRepo { base: PathBuf::from(path) }));
    }
    if r.starts_with('/') {
        return Ok(Box::new(FileRepo { base: PathBuf::from(r) }));
    }
    #[cfg(feature = "http")]
    if r.starts_with("https://") || (cfg.allow_http && r.starts_with("http://")) {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(cfg.http_timeout)))
            .https_only(!cfg.allow_http)
            .user_agent(concat!("pve-klp/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        return Ok(Box::new(HttpRepo { base: r.trim_end_matches('/').to_owned(), agent }));
    }
    bail!("unsupported repository URL {r:?}: use https://, file:// or an absolute path")
}

fn check_rel(rel: &str) -> Result<()> {
    if rel.starts_with('/') || rel.split('/').any(|c| c.is_empty() || c == "." || c == "..") {
        bail!("refusing suspicious repository path {rel:?}");
    }
    Ok(())
}

pub struct FileRepo {
    pub base: PathBuf,
}

impl Repo for FileRepo {
    fn get(&self, rel: &str, max: u64) -> Result<Vec<u8>, RepoError> {
        check_rel(rel)?;
        let p = self.base.join(rel);
        match std::fs::metadata(&p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(RepoError::NotFound(rel.into())),
            Err(e) => return Err(anyhow::Error::from(e).context(format!("stat {}", p.display())).into()),
            Ok(m) if m.len() > max => return Err(anyhow::anyhow!("{rel} exceeds {max} bytes").into()),
            Ok(_) => {}
        }
        Ok(std::fs::read(&p).with_context(|| format!("reading {}", p.display()))?)
    }

    fn describe(&self) -> String {
        format!("file://{}", self.base.display())
    }
}

#[cfg(feature = "http")]
pub struct HttpRepo {
    base: String,
    agent: ureq::Agent,
}

#[cfg(feature = "http")]
impl Repo for HttpRepo {
    fn get(&self, rel: &str, max: u64) -> Result<Vec<u8>, RepoError> {
        check_rel(rel)?;
        let url = format!("{}/{rel}", self.base);
        let mut resp = match self.agent.get(&url).call() {
            Ok(r) => r,
            Err(ureq::Error::StatusCode(404)) => return Err(RepoError::NotFound(rel.into())),
            Err(e) => return Err(anyhow::Error::from(e).context(format!("GET {url}")).into()),
        };
        let body =
            resp.body_mut().with_config().limit(max).read_to_vec().with_context(|| format!("reading body of {url}"))?;
        Ok(body)
    }

    fn describe(&self) -> String {
        self.base.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_repo_and_path_checks() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("v1/k")).unwrap();
        std::fs::write(t.path().join("v1/k/a"), b"hello").unwrap();
        let r = FileRepo { base: t.path().into() };
        assert_eq!(r.get("v1/k/a", 10).unwrap(), b"hello");
        assert!(matches!(r.get("v1/k/b", 10), Err(RepoError::NotFound(_))));
        assert!(r.get("v1/k/a", 2).is_err());
        assert!(r.get("../etc/passwd", 10).is_err());
        assert!(r.get("v1//a", 10).is_err());
    }

    #[cfg(feature = "http")]
    #[test]
    fn url_schemes() {
        let mut c = Config { repository: "ftp://x".into(), ..Default::default() };
        assert!(open(&c).is_err());
        c.repository = "http://x".into();
        assert!(open(&c).is_err());
        c.allow_http = true;
        assert!(open(&c).is_ok());
        c.repository = "https://klp.example.org/".into();
        assert_eq!(open(&c).unwrap().describe(), "https://klp.example.org");
    }
}
